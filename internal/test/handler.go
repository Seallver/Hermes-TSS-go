package test

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"log"
	"net/http"
	"sync"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network INetwork) {
	for {
		//log.Println("handlerLoop")
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				log.Println("Work done")
				//<-network.Done(id)
				//log.Println("Loop done")
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			ms, _ := msg.MarshalJson()
			log.Printf("Loop outgoing  id:%s msg:%s /n", id, ms)
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			ms, _ := msg.MarshalJson()
			log.Printf("Loop incoming  id:%s msg:%s /n", id, ms)
			h.Accept(msg)
		}
	}
}

func WebHandlerLoop(c *gin.Context, id party.ID, h protocol.Handler, network INetwork, cond_ *sync.Cond) {

	for {
		//log.Println("handlerLoop")
		select {
		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				log.Println("Work done")
				//<-network.Done(id)
				//log.Println("Loop done")
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			ms, _ := msg.MarshalJson()
			cond_.L.Lock()
			c.String(http.StatusOK, fmt.Sprintf("Loop outgoing id:%s msg:%s ", id, ms))
			//if ms != nil {
			//	c.HTML(200, "HermesTest.html", gin.H{"Loop_outgoing_data": fmt.Sprintf("Loop outgoing id:%s msg:%s ", id, ms)})
			//}
			cond_.L.Unlock()
			go network.Send(msg)
		// incoming messages
		case msg := <-network.Next(id):
			ms, _ := msg.MarshalJson()
			cond_.L.Lock()
			c.String(http.StatusOK, fmt.Sprintf("Loop incoming id:%s msg:%s ", id, ms))
			//if ms != nil {
			//	c.HTML(200, "HermesTest.html", gin.H{"Loop_incoming_data": fmt.Sprintf("Loop incoming id:%s msg:%s ", id, ms)})
			//}
			cond_.L.Unlock()
			h.Accept(msg)
		}
	}
}
