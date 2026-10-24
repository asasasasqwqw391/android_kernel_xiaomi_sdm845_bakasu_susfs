#!/usr/bin/env python3
"""Fix two bugs in KernelSU's do_persistent_allow_list() on this 4.9 tree.

BUG 1 (crash): ksu_persistent_allow_list() runs the worker through
ksu_run_in_init_if_possible(), so the function body executes on the **init**
task. It does override_creds(ksu_cred) and then, when filp_open() fails,
returns without revert_creds(). init is left with cred != real_cred, and the
next selinux_setprocattr() -> commit_creds() hits

    kernel BUG at kernel/cred.c:435   (BUG_ON(task->cred != old))

which panics the device. Any allowlist change can therefore set a time bomb
that fires the next time init starts a service (enabling wifi/hotspot is a
reliable trigger, because init then spawns wpa_supplicant).

BUG 2 (persistence): the open itself fails with -ENOKEY, so the allowlist is
never written and every root grant is lost on reboot. Retry once with the
caller's creds, which are init's and therefore fully privileged.

Both fixes are local to this function; the on-disk format is unchanged.
"""
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else 'KernelSU/kernel/policy/allowlist.c'

OLD_OPEN = '''    const struct cred *saved = override_creds(ksu_cred);
    fp = filp_open(KERNEL_SU_ALLOWLIST, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("save_allow_list create file failed: %ld\\n", PTR_ERR(fp));
        return;
    }
'''

NEW_OPEN = '''    const struct cred *saved = override_creds(ksu_cred);
    fp = filp_open(KERNEL_SU_ALLOWLIST, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        long open_err = PTR_ERR(fp);

        /*
         * This worker runs on the init task (ksu_run_in_init_if_possible), so
         * bailing out here without revert_creds() would leave init with an
         * overridden subjective cred and the next commit_creds() would trip
         * BUG_ON(task->cred != old). Always revert first.
         */
        revert_creds(saved);
        saved = NULL;

        /*
         * ksu_cred carries the session keyring captured at second-stage boot,
         * which on this device cannot resolve /data (open returns -ENOKEY), so
         * the allowlist was never persisted and every grant died on reboot.
         * Retry with the caller's creds -- we are init, so we are privileged.
         */
        pr_warn("save_allow_list: open with ksu_cred failed: %ld, retrying with caller creds\\n",
                open_err);
        fp = filp_open(KERNEL_SU_ALLOWLIST, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (IS_ERR(fp)) {
            pr_err("save_allow_list create file failed: %ld\\n", PTR_ERR(fp));
            return;
        }
    }
'''

OLD_OUT = '''out:
    revert_creds(saved);
    filp_close(fp, 0);
'''

NEW_OUT = '''out:
    if (saved)
        revert_creds(saved);
    filp_close(fp, 0);
'''

src = open(PATH).read()

for old, new, what in ((OLD_OPEN, NEW_OPEN, 'open/revert block'), (OLD_OUT, NEW_OUT, 'out label')):
    if old not in src:
        sys.exit('ERROR: %s anchor not found in %s -- upstream code changed, review the patch'
                 % (what, PATH))
    if src.count(old) != 1:
        sys.exit('ERROR: %s anchor is not unique in %s' % (what, PATH))
    src = src.replace(old, new, 1)

open(PATH, 'w').write(src)
print('patched %s: revert_creds leak + keyring fallback' % PATH)
