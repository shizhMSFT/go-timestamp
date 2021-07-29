# go-timestamp

This library generates time stamping requests to TSA servers, and fetches the responses.

By default, the received token is verified against the system trust store.

## Install

```sh
go get github.com/shizhMSFT/go-timestamp
```

## Example

```go
package main

import (
	"context"
	"fmt"
	"log"

	_ "crypto/sha256"

	"github.com/opencontainers/go-digest"
	"github.com/shizhMSFT/go-timestamp"
)

func main() {
	req, err := timestamp.NewRequest(digest.FromString("hello"))
	if err != nil {
		log.Fatal(err)
	}
	req.CertReq = true

	ts := timestamp.NewHTTPTimestamper(nil, "http://timestamp.sectigo.com")
	resp, err := ts.Timestamp(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("status:", resp.Status.Status)
	info, err := resp.TimeStampTokenInfo()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("time:", info.GenTime)
	fmt.Println("serial:", info.SerialNumber)
}
```

Output:

```
status: 0
time: 2021-07-29 11:07:04 +0000 UTC
serial: 830360054253615705123898671080818616295644417367
```
