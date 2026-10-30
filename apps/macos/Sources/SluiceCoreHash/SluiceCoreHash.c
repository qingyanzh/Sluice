#include "SluiceCoreHash.h"

// Patched after linking and before signing the helper. Volatile prevents constant folding;
// used keeps a patchable slot in every architecture of a universal helper.
__attribute__((used)) static volatile char core_cdhash[200] = "SLUICE-CORE-CDHASH:";

const volatile char *sluice_core_cdhash_slot(void) {
    return core_cdhash + sizeof("SLUICE-CORE-CDHASH:") - 1;
}
