#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "lwip/api.h"

#include "include/r2r.h"
#include "include/network.h"
#include "include/packet_buffer.h"


pkt_b *packet_queue;
int rear, front;
int size;
int current_item = 0;
const size_t pkt_b_size_ = sizeof(pkt_b);

pkt_b *pkt_b_default;

void init_pkt_queue(int max)
{
    packet_queue = malloc(max * pkt_b_size_);
    pkt_b_default = malloc(pkt_b_size_);
    memset(pkt_b_default,0,pkt_b_size_);
    size = max;
    front = rear = -1; 
}

void buffer_add(pkt_b value) 
{ 
    if ((front == 0 && rear == size-1) || 
            (rear == (front-1)%(size-1))) 
    {
        return; 
    } 
  
    else if (front == -1) /* Insert First Element */
    { 
        front = rear = 0; 
        packet_queue[rear] = value; 
    } 
  
    else if (rear == size-1 && front != 0) 
    { 
        rear = 0; 
        packet_queue[rear] = value; 
    } 
  
    else
    { 
        rear++; 
        packet_queue[rear] = value; 
    } 
    current_item++;
} 
  
// Function to delete element from Circular Queue 
pkt_b* buffer_get() 
{ 
    if (front == -1) 
    { 
        return NULL; 
    } 
    pkt_b *data = malloc(pkt_b_size_); 
    memcpy(data,&packet_queue[front],pkt_b_size_);
    if (front == rear)
    { 
        front = -1; 
        rear = -1; 
    }
    else if (front == size-1) 
        front = 0; 
    else
        front++; 
    current_item--;
    return data; 
}

int get_items_count()
{
    return current_item;
}