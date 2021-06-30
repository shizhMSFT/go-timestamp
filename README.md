# go-timestamp

This library generates time stamping requests to TSA servers, and fetches the responses.

> Note: Although this library can read the time stamp token info, it does not verify the token.

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
		panic(err)
	}
	fmt.Println("time:", info.GenTime)
	fmt.Println("serial:", info.SerialNumber)
}
```