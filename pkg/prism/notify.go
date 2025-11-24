package prism

type Notifier interface {
	NotifyDone()
	NotifyError(err error)
	Done() <-chan struct{}
	Error() <-chan error
}

type notifier struct {
	doneCh chan struct{}
	errCh  chan error
}

func NewNotifier() Notifier {
	return &notifier{
		doneCh: make(chan struct{}, 1),
		errCh:  make(chan error, 1),
	}
}

func (n *notifier) NotifyDone() {
	if n == nil {
		return
	}

	select {
	case n.doneCh <- struct{}{}:
	default:
	}
}

func (n *notifier) NotifyError(err error) {
	if n == nil {
		return
	}

	select {
	case n.errCh <- err:
	default:
	}
}

func (n *notifier) Done() <-chan struct{} { return n.doneCh }
func (n *notifier) Error() <-chan error   { return n.errCh }
