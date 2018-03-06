import time
import angr
import hashlib

def main():
    p = angr.Project('RedVelvet')

    st = p.factory.entry_state(args=['./RedVelvet'], add_options={"BYPASS_UNSUPPORTED_SYSCALL"})
    for _ in xrange(26):
        k = st.posix.files[0].read_from(1)
        # flags are always printable characters
        st.solver.add(k >= 0x20)
        st.solver.add(k <= 0x7E)

    st.posix.files[0].seek(0)
    st.posix.files[0].length = 26

    sm = p.factory.simulation_manager(st)

    fn_rets = [
        0x004012af,
        0x004012d2,
        0x004012f5,
        0x00401318,
        0x0040133b,
        0x00401368,
        0x00401395,
        0x004013c2,
        0x004013ef,
        0x00401446,
        0x00401473,
        0x004014a0,
        0x004014cd,
        0x004014fa,
        0x00401527]

    print("Starting...")
    for (num, addr) in enumerate(fn_rets, start=1):
        sm.explore(find=addr).unstash(from_stash='found', to_stash='active')
        print("past func{0}".format(num))

    final = sm.active[0]
    flag_hash = '0a435f46288bb5a764d13fca6c901d3750cee73fd7689ce79ef6dc0ff8f380e5'

    print("Solving for flags...")
    flags = final.solver.eval_upto(final.posix.files[0].content.load(0, 26), 500, cast_to=str)
    print("Bruteforcing flag...")
    for flag in flags:
        if flag_hash == hashlib.sha256(flag).hexdigest():
            return flag

    # takes about 7 mins on my Broadwell i5

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
