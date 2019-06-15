#include "freertos/FreeRTOS.h"
#include <string.h>

#include "include/command.h"    

r2r_command *packet_queue;
int rear, front;
int size;
int current_item = 0;
const size_t cmd_size_ = sizeof(r2r_command);
bool repeat = false;

r2r_command *pkt_b_default;

void init_cmd_queue(int max)
{
    packet_queue = malloc(max * cmd_size_);
    pkt_b_default = malloc(cmd_size_);
    memset(pkt_b_default,0,cmd_size_);
    size = max;
    front = rear = -1; 
}

void buffer_add(r2r_command value) 
{
    if(current_item + 1 > size) return;
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
r2r_command* buffer_get() 
{ 
    if (front == -1) 
    { 
        return NULL; 
    } 
    r2r_command *data = malloc(cmd_size_); 
    memcpy(data,&packet_queue[front],cmd_size_);
    if (front == rear)
    { 
        if(!repeat)
        {
            front = -1; 
            rear = -1; 
        }
        else
        {
            front = front - current_item;   
        }
    }
    else if (front == size-1) 
        front = 0; 
    else
        front++; 
    if(!repeat)
    {
        current_item--;
    }
    return data; 
}

int get_items_count()
{
    return current_item;
}

void set_repeat(bool is_repeat)
{
    repeat = is_repeat;
}