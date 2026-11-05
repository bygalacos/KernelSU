#include "compat/jailbreak.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

static void *defex_enforce_fn;
static int defex_allow(void)
{
    return 0;
}

void defex_jb_init(void)
{
    void *new_fn = defex_allow;

    defex_enforce_fn = (void *)ksu_resolve_symbol_for_functable_hook("task_defex_enforce");
    if (!defex_enforce_fn)
        return;

    if (ksu_rkp_branch_patch(&defex_enforce_fn, &new_fn)) {
        pr_warn("KSU: DEFEX patch failed\n");
        defex_enforce_fn = NULL;
        return;
    }
    pr_info("KSU: Samsung DEFEX detected\n");
}

void defex_jb_exit(void)
{
    /* Restore task_defex_enforce before rkp_jb_exit() frees the stub page,
     * else the site points into freed module text (UAF on unload). Same fn
     * for dst and src takes the restore-and-remove path. */
    if (!defex_enforce_fn)
        return;
    ksu_rkp_branch_patch(&defex_enforce_fn, &defex_enforce_fn);
}
