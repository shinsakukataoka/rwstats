#include "drmemtrace/analysis_tool.h"
#include "drmemtrace/memref.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

using namespace dynamorio::drmemtrace;

// -------- helpers --------
static inline uint64_t line_id(uint64_t addr) { return addr >> 6; }   // 64B lines
static inline uint64_t page_id(uint64_t addr) { return addr >> 12; }  // 4KB pages
static inline uint64_t iabs64(int64_t x){ return x < 0 ? -x : x; }

static inline uint64_t env_u64(const char *key, uint64_t defv){
    const char *s = getenv(key);
    if(!s || !*s) return defv;
    char *end=nullptr;
    uint64_t v = strtoull(s,&end,10);
    return end && *end==0 ? v : defv;
}
static inline int env_int(const char *key, int defv){
    const char *s = getenv(key);
    if(!s || !*s) return defv;
    return atoi(s);
}

class rwstats_tool_t : public analysis_tool_t {
public:
    rwstats_tool_t()
    : interval_target_(env_u64("RWSTATS_INTERVAL", 5000000)),
      stride_cap_bytes_(env_u64("RWSTATS_STRIDE_CAP_BYTES", (1ull<<20))),
      local_mask_bits_(env_int("RWSTATS_LOCAL_BITS", 10)),
      disable_stride_(env_int("RWSTATS_DISABLE_STRIDE", 0)),
      want_final_lines_(env_int("RWSTATS_FINAL_LINES", 1) != 0)
    {
        if (stride_cap_bytes_ == 0) stride_cap_bytes_ = (1ull<<20);
        // histogram bins based on log2(cap)
        max_log2_byte_ = 0;
        uint64_t c = stride_cap_bytes_;
        while (c >>= 1) ++max_log2_byte_;
        if (max_log2_byte_ < 1) max_log2_byte_ = 1;
        histB_.assign(max_log2_byte_+1, 0);
        histL_.assign(17, 0); // line strides: up to 2^16 lines (8MB/64B) -> 17 bins (0..16)
    }

    // --- analysis_tool_t required ---
    bool process_memref(const memref_t &m) override {
        const trace_type_t t = m.data.type;
        if (t != TRACE_TYPE_READ && t != TRACE_TYPE_WRITE)
            return true;

        const uint64_t addr = m.data.addr;
        const uint64_t sz   = m.data.size ? m.data.size : 1;

        // global totals
        if (t == TRACE_TYPE_READ) { reads_++;  bytes_read_  += sz; }
        else                      { writes_++; bytes_written_+= sz; }

        // interval uniques
        interval_lines_.insert(line_id(addr));
        interval_pages_.insert(page_id(addr));

        // per-type interval uniques (addresses)
        if (t == TRACE_TYPE_READ) {
            rd_addr_set_.insert(addr);
            rd_total_interval_++;
        } else {
            wr_addr_set_.insert(addr);
            wr_total_interval_++;
        }

        // local-mask address for "local entropy proxy"
        const uint64_t local_mask = ~((1ull << local_mask_bits_) - 1);
        const uint64_t rd_key = (t == TRACE_TYPE_READ) ? (addr & local_mask) : 0;
        const uint64_t wr_key = (t == TRACE_TYPE_WRITE) ? (addr & local_mask) : 0;

        // address histos for entropy (interval)
        if (t == TRACE_TYPE_READ) {
            rd_freq_[addr]++;
            rd_local_freq_[rd_key]++;
        } else {
            wr_freq_[addr]++;
            wr_local_freq_[wr_key]++;
        }

        // final-only line-level per-type bookkeeping (unique & frequency -> 90% footprint)
        if (want_final_lines_) {
            const uint64_t lid = line_id(addr);
            if (t == TRACE_TYPE_READ) { rd_lines_set_.insert(lid); rd_line_freq_[lid]++; }
            else                      { wr_lines_set_.insert(lid); wr_line_freq_[lid]++; }
        }

        // stride stats (interval)
        if (!disable_stride_) {
            if (have_last_) {
                uint64_t dB = iabs64((int64_t)addr - (int64_t)last_addr_);
                uint64_t dL = iabs64((int64_t)line_id(addr) - (int64_t)line_id(last_addr_));

                if (dB > stride_cap_bytes_) { dB = stride_cap_bytes_; stride_bytes_over_cap_++; }
                if (dL > (1u<<16))          { dL = (1u<<16);         line_stride_over_cap_++; }

                sum_strideB_ += (double)dB;
                sum_strideL_ += (double)dL;
                stride_cnt_  += 1;

                // <=64B fraction
                if (dB <= 64) le64_cnt_++;

                // histograms for percentiles (log2 bins)
                uint32_t bB = (dB==0)?0: (uint32_t)std::min<uint32_t>(max_log2_byte_, 63 - __builtin_clzll(dB));
                histB_[bB]++;

                uint32_t bL = (dL==0)?0: (uint32_t)std::min<uint32_t>(16u, (uint32_t)(63 - __builtin_clzll(dL)));
                histL_[bL]++;
            }
            last_addr_ = addr;
            have_last_ = true;
        }

        // interval emission
        if (interval_target_ > 0 && (reads_+writes_ - last_emit_total_) >= interval_target_) {
            emit_interval();
            clear_interval();
        }
        return true;
    }

    bool print_results() override {
        // ensure a last interval print if user set RWSTATS_INTERVAL=0
        if (last_emit_total_ == 0 && (reads_+writes_) > 0 && interval_target_==0) {
            emit_interval();
            clear_interval();
        }

        // final-only line stats (unique + 90% footprint) on top of the usual final summary
        uint64_t rd_uniqL = 0, wr_uniqL = 0, rd_fp90L = 0, wr_fp90L = 0;
        if (want_final_lines_) {
            rd_uniqL = (uint64_t)rd_lines_set_.size();
            wr_uniqL = (uint64_t)wr_lines_set_.size();
            rd_fp90L = footprint90_from_freq(rd_line_freq_, total_reads_seen());
            wr_fp90L = footprint90_from_freq(wr_line_freq_, total_writes_seen());
        }

        // Reuse last computed interval aggregates as proxies for scope=final
        // (we already printed interval snapshots; final carries totals)
        const char *scope = "final";
        double avgB = (stride_cnt_>0) ? (sum_strideB_/stride_cnt_) : NAN;
        double avgL = (stride_cnt_>0) ? (sum_strideL_/stride_cnt_) : NAN;
        double pLE64= (stride_cnt_>0) ? ((double)le64_cnt_/stride_cnt_) : NAN;

        uint64_t p50B=0,p90B=0,p99B=0, p50L=0,p90L=0,p99L=0;
        approx_percentiles(p50B,p90B,p99B,histB_, stride_cap_bytes_, true);
        approx_percentiles(p50L,p90L,p99L,histL_, (1ull<<16), false);

        // interval uniques at this moment
        uint64_t uniq_lines = interval_lines_.size();
        uint64_t uniq_pages = interval_pages_.size();
        uint64_t fp_bytes   = uniq_lines * 64ull;

        // address-entropy per interval proxy
        double Hs = entropy_from_freq(stride_cnt_==0 ? empty_freq_ : stride_dummy_); // leave H_stride realistic below
        // real stride entropy using byte histogram
        Hs = entropy_from_hist(histB_);

        // read/write interval counters and entropies
        double Hrg=entropy_from_freq(rd_freq_), Hrl=entropy_from_freq(rd_local_freq_);
        double Hwg=entropy_from_freq(wr_freq_), Hwl=entropy_from_freq(wr_local_freq_);

        // reuse rate proxy (seen-before within interval)
        double reuse = reuse_rate_proxy(rd_freq_, wr_freq_);

        fprintf(stdout,
            "scope=%s,reads=%" PRIu64 ",writes=%" PRIu64
            ",bytes_read=%" PRIu64 ",bytes_written=%" PRIu64
            ",uniq_lines=%" PRIu64 ",uniq_pages=%" PRIu64 ",footprint_bytes=%" PRIu64
            ",H_line=%s,H_page=%s,H_stride=%.6f"
            ",reuse_rate=%.6f,avg_stride=%s,avg_line_stride=%s,p_stride_le_64=%s"
            ",p50_strideB=%" PRIu64 ",p90_strideB=%" PRIu64 ",p99_strideB=%" PRIu64
            ",p50_strideL=%" PRIu64 ",p90_strideL=%" PRIu64 ",p99_strideL=%" PRIu64
            ",stride_bytes_over_cap=%" PRIu64 ",line_stride_over_cap=%" PRIu64
            ",read_total=%" PRIu64 ",read_unique=%" PRIu64 ",read_entropy=%.6f,read_local_entropy=%.6f,read_footprint90=%" PRIu64
            ",write_total=%" PRIu64 ",write_unique=%" PRIu64 ",write_entropy=%.6f,write_local_entropy=%.6f,write_footprint90=%" PRIu64
            "%s%s"
            "\n",
            scope, reads_, writes_,
            bytes_read_, bytes_written_,
            uniq_lines, uniq_pages, fp_bytes,
            "nan","nan", Hs,
            reuse,
            fmt_double(avgB).c_str(), fmt_double(avgL).c_str(), fmt_double(pLE64).c_str(),
            p50B,p90B,p99B, p50L,p90L,p99L,
            stride_bytes_over_cap_, line_stride_over_cap_,
            rd_total_interval_, (uint64_t)rd_addr_set_.size(), Hrg, Hrl, (uint64_t)0,
            wr_total_interval_, (uint64_t)wr_addr_set_.size(), Hwg, Hwl, (uint64_t)0,
            // optional final-only extras at the very end (if enabled)
            want_final_lines_ ? ",read_unique_lines=" : "",
            want_final_lines_ ? (fmt_u64(rd_uniqL)+",write_unique_lines="+fmt_u64(wr_uniqL)+
                                 ",read_footprint90L="+fmt_u64(rd_fp90L)+
                                 ",write_footprint90L="+fmt_u64(wr_fp90L)).c_str() : ""
        );
        return true;
    }

private:
    // ----- state -----
    uint64_t reads_ = 0, writes_ = 0;
    uint64_t bytes_read_ = 0, bytes_written_ = 0;

    // interval knobs
    uint64_t interval_target_;
    uint64_t last_emit_total_ = 0;

    // stride stats (interval)
    uint64_t stride_cap_bytes_;
    uint32_t max_log2_byte_ = 20;
    int      local_mask_bits_;
    int      disable_stride_;
    bool     have_last_ = false;
    uint64_t last_addr_ = 0;
    uint64_t stride_cnt_ = 0;
    uint64_t le64_cnt_ = 0;
    uint64_t stride_bytes_over_cap_ = 0;
    uint64_t line_stride_over_cap_  = 0;
    double   sum_strideB_ = 0.0, sum_strideL_ = 0.0;
    std::vector<uint64_t> histB_, histL_;

    // interval uniques
    std::unordered_set<uint64_t> interval_lines_;
    std::unordered_set<uint64_t> interval_pages_;

    // per-type address stats (interval)
    std::unordered_map<uint64_t,uint32_t> rd_freq_, wr_freq_;
    std::unordered_map<uint64_t,uint32_t> rd_local_freq_, wr_local_freq_;
    std::unordered_set<uint64_t> rd_addr_set_, wr_addr_set_;
    uint64_t rd_total_interval_ = 0, wr_total_interval_ = 0;

    // final-only line per-type
    const bool want_final_lines_;
    std::unordered_set<uint64_t> rd_lines_set_, wr_lines_set_;
    std::unordered_map<uint64_t,uint32_t> rd_line_freq_, wr_line_freq_;

    // dummies
    std::unordered_map<uint64_t,uint32_t> stride_dummy_;
    std::unordered_map<uint64_t,uint32_t> empty_freq_;

    // ----- helpers -----
    uint64_t total_reads_seen()  const { return reads_; }
    uint64_t total_writes_seen() const { return writes_; }

    static double entropy_from_freq(const std::unordered_map<uint64_t,uint32_t> &f){
        if (f.empty()) return NAN;
        double H=0.0, N=0.0;
        for (auto &kv : f) N += kv.second;
        if (N <= 0) return NAN;
        for (auto &kv : f) {
            double p = kv.second / N;
            if (p>0) H -= p * std::log2(p);
        }
        return H;
    }
    static double entropy_from_hist(const std::vector<uint64_t> &h){
        uint64_t N=0; for(auto v: h) N+=v;
        if (N==0) return NAN;
        double H=0.0;
        for(size_t i=0;i<h.size();++i){
            if (!h[i]) continue;
            double p = (double)h[i]/(double)N;
            H -= p*std::log2(p);
        }
        return H;
    }
    static std::string fmt_double(double v){
        if (std::isnan(v)) return std::string("nan");
        char b[64]; snprintf(b,sizeof(b),"%.6f", v); return std::string(b);
    }
    static std::string fmt_u64(uint64_t v){
        char b[64]; snprintf(b,sizeof(b),"%" PRIu64, v); return std::string(b);
    }

    // approximate percentiles from log2 histogram
    static void approx_percentiles(uint64_t &p50,uint64_t &p90,uint64_t &p99,
                                   const std::vector<uint64_t> &h,
                                   uint64_t cap, bool bytes)
    {
        uint64_t N=0; for(auto v: h) N+=v;
        if (N==0){ p50=p90=p99=0; return; }
        const uint64_t t50 = (N*50 + 99)/100;
        const uint64_t t90 = (N*90 + 99)/100;
        const uint64_t t99 = (N*99 + 99)/100;

        uint64_t acc=0; p50=0; p90=0; p99=0;
        for (size_t b=0;b<h.size();++b) {
            acc += h[b];
            uint64_t val = (b==0)?0: (1ull<<b);
            if (bytes && val>cap) val=cap;
            if (!p50 && acc>=t50) p50 = val;
            if (!p90 && acc>=t90) p90 = val;
            if (!p99 && acc>=t99) { p99 = val; break; }
        }
        if (p50==0 && N) p50=1;
        if (p90==0 && N) p90=1;
        if (p99==0 && N) p99=1;
    }

    static uint64_t footprint90_from_freq(const std::unordered_map<uint64_t,uint32_t> &freq,
                                          uint64_t total_ops)
    {
        if (freq.empty() || total_ops==0) return 0;
        std::vector<uint32_t> v; v.reserve(freq.size());
        for (auto &kv: freq) v.push_back(kv.second);
        std::sort(v.begin(), v.end(), std::greater<uint32_t>());

        uint64_t need = (uint64_t)std::ceil(total_ops * 0.90);
        uint64_t sum=0, cnt=0;
        for (auto c: v){ sum += c; cnt++; if (sum >= need) break; }
        return cnt;
    }

    double reuse_rate_proxy(const std::unordered_map<uint64_t,uint32_t>& rf,
                            const std::unordered_map<uint64_t,uint32_t>& wf) const
    {
        uint64_t seen = 0, total = 0;
        for (auto &kv: rf){ total += kv.second; if (kv.second>1) seen += (kv.second-1); }
        for (auto &kv: wf){ total += kv.second; if (kv.second>1) seen += (kv.second-1); }
        if (total==0) return NAN;
        return (double)seen/(double)total;
    }

    void emit_interval(){
        // Compute interval aggregates and print one "scope=interval" line.
        const char *scope = "interval";

        double avgB = (stride_cnt_>0) ? (sum_strideB_/stride_cnt_) : NAN;
        double avgL = (stride_cnt_>0) ? (sum_strideL_/stride_cnt_) : NAN;
        double pLE64= (stride_cnt_>0) ? ((double)le64_cnt_/stride_cnt_) : NAN;

        uint64_t p50B=0,p90B=0,p99B=0, p50L=0,p90L=0,p99L=0;
        approx_percentiles(p50B,p90B,p99B,histB_, stride_cap_bytes_, true);
        approx_percentiles(p50L,p90L,p99L,histL_, (1ull<<16), false);

        uint64_t uniq_lines = interval_lines_.size();
        uint64_t uniq_pages = interval_pages_.size();
        uint64_t fp_bytes   = uniq_lines * 64ull;

        double Hs  = entropy_from_hist(histB_);
        double Hrg = entropy_from_freq(rd_freq_), Hrl=entropy_from_freq(rd_local_freq_);
        double Hwg = entropy_from_freq(wr_freq_), Hwl=entropy_from_freq(wr_local_freq_);
        double reuse = reuse_rate_proxy(rd_freq_, wr_freq_);

        fprintf(stdout,
            "scope=%s,reads=%" PRIu64 ",writes=%" PRIu64
            ",bytes_read=%" PRIu64 ",bytes_written=%" PRIu64
            ",uniq_lines=%" PRIu64 ",uniq_pages=%" PRIu64 ",footprint_bytes=%" PRIu64
            ",H_line=%s,H_page=%s,H_stride=%.6f"
            ",reuse_rate=%.6f,avg_stride=%s,avg_line_stride=%s,p_stride_le_64=%s"
            ",p50_strideB=%" PRIu64 ",p90_strideB=%" PRIu64 ",p99_strideB=%" PRIu64
            ",p50_strideL=%" PRIu64 ",p90_strideL=%" PRIu64 ",p99_strideL=%" PRIu64
            ",stride_bytes_over_cap=%" PRIu64 ",line_stride_over_cap=%" PRIu64
            ",read_total=%" PRIu64 ",read_unique=%" PRIu64 ",read_entropy=%.6f,read_local_entropy=%.6f,read_footprint90=%" PRIu64
            ",write_total=%" PRIu64 ",write_unique=%" PRIu64 ",write_entropy=%.6f,write_local_entropy=%.6f,write_footprint90=%" PRIu64
            "\n",
            scope, reads_, writes_,
            bytes_read_, bytes_written_,
            uniq_lines, uniq_pages, fp_bytes,
            "nan","nan", Hs,
            reuse,
            fmt_double(avgB).c_str(), fmt_double(avgL).c_str(), fmt_double(pLE64).c_str(),
            p50B,p90B,p99B, p50L,p90L,p99L,
            stride_bytes_over_cap_, line_stride_over_cap_,
            rd_total_interval_, (uint64_t)rd_addr_set_.size(), Hrg, Hrl, (uint64_t)0,
            wr_total_interval_, (uint64_t)wr_addr_set_.size(), Hwg, Hwl, (uint64_t)0
        );
        last_emit_total_ = reads_+writes_;
    }

    void clear_interval(){
        interval_lines_.clear();
        interval_pages_.clear();
        rd_freq_.clear(); wr_freq_.clear();
        rd_local_freq_.clear(); wr_local_freq_.clear();
        rd_addr_set_.clear(); wr_addr_set_.clear();
        rd_total_interval_ = 0; wr_total_interval_ = 0;

        stride_cnt_ = 0; le64_cnt_ = 0;
        sum_strideB_ = 0.0; sum_strideL_ = 0.0;
        stride_bytes_over_cap_ = 0; line_stride_over_cap_ = 0;
        std::fill(histB_.begin(), histB_.end(), 0);
        std::fill(histL_.begin(), histL_.end(), 0);
        have_last_ = false;
        last_addr_ = 0;
    }
};

analysis_tool_t *rwstats_tool_create() { return new rwstats_tool_t(); }
