package internal

import "golang.org/x/sys/unix"

type linkOps struct {
	socket     func(domain, typ, proto int) (int, error)
	newIfreq   func(name string) (*unix.Ifreq, error)
	ioctlIfreq func(fd int, req uint, ifr *unix.Ifreq) error
	close      func(fd int) error
}

func ensureLoopbackUp() error {
	return ensureLoopbackUpWith(linkOps{
		socket:     unix.Socket,
		newIfreq:   unix.NewIfreq,
		ioctlIfreq: unix.IoctlIfreq,
		close:      unix.Close,
	})
}

func ensureLoopbackUpWith(ops linkOps) error {
	fd, err := ops.socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = ops.close(fd)
	}()

	ifr, err := ops.newIfreq("lo")
	if err != nil {
		return err
	}
	ifr.SetUint16(unix.IFF_UP)
	return ops.ioctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
