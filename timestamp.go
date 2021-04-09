package timestamp

import (
	"context"
)

// Timestamper stamps the time
type Timestamper interface {
	Timestamp(context.Context, *Request) (*Response, error)
}
