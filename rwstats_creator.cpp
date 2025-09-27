#include "drmemtrace/analysis_tool.h"
using namespace dynamorio::drmemtrace;
analysis_tool_t *rwstats_tool_create();

#if defined(_WIN32)
#  define EXPORT __declspec(dllexport)
#else
#  define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {
EXPORT const char *get_tool_name() { return "rwstats"; }
EXPORT analysis_tool_t *analysis_tool_create() { return rwstats_tool_create(); }
}
