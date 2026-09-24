package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const reconcileURL = "https://reconcile.internal.example/api/shipments"

// ShipmentEvent 是倉儲系統的出貨事件，批次轉送給對帳服務。
type ShipmentEvent struct {
	OrderID   string    `json:"order_id"`
	SKU       string    `json:"sku"`
	Quantity  int       `json:"quantity"`
	ShippedAt time.Time `json:"shipped_at"`
	Checksum  string    `json:"checksum"`
}

// withChecksum 為每筆事件加上校驗碼，對帳服務用它比對兩邊資料是否一致。
func withChecksum(events []ShipmentEvent) {
	for i := range events {
		e := &events[i]
		raw := fmt.Sprintf("%s|%s|%d|%d", e.OrderID, e.SKU, e.Quantity, e.ShippedAt.Unix())
		sum := md5.Sum([]byte(raw))
		e.Checksum = hex.EncodeToString(sum[:])
	}
}

func forwardShipments(client *http.Client, events []ShipmentEvent) error {
	withChecksum(events)
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	resp, err := client.Post(reconcileURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reconcile service: %s", resp.Status)
	}
	return nil
}
