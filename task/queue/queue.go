package queue

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/panjf2000/ants/v2"
)

// TaskQueue representation of task queue.
type TaskQueue struct {
	goPool             *ants.Pool
	limit              int
	numParallelRequest int

	mutex sync.Mutex
	queue *list.List
}

// New creates task queue which is processed by number of workers. Number of task is limited by limit.
func New(numWorkers, limit int, options ...ants.Option) (*TaskQueue, error) {
	options = append(options, ants.WithNonblocking(true))
	p, err := ants.NewPool(numWorkers, options...)
	if err != nil {
		return nil, err
	}
	return &TaskQueue{
		queue:              list.New(),
		goPool:             p,
		limit:              limit,
		numParallelRequest: numWorkers,
	}, nil
}

func (q *TaskQueue) appendQueue(tasks []func()) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.queue.Len()+len(tasks) > q.limit {
		return fmt.Errorf("reached limit of max processed jobs")
	}
	for _, t := range tasks {
		q.queue.PushBack(t)
	}
	return nil
}

func (q *TaskQueue) popQueue() func() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if q.queue.Len() == 0 {
		return nil
	}
	return q.queue.Remove(q.queue.Front()).(func())
}

// Submit appends and execute task by taskQueue.
func (q *TaskQueue) Submit(tasks ...func()) error {
	err := q.appendQueue(tasks)
	if err != nil {
		return err
	}
	q.goPool.Submit(func() {
		for {
			task := q.popQueue()
			if task == nil {
				return
			}
			task()
		}
	})
	return nil
}

// Release closes queue and release it.
func (q *TaskQueue) Release() {
	q.goPool.Release()
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.queue.Init()
}
