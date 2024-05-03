#ifndef QUEUE_H
#define QUEUE_H

#include <stdio.h>
#include <stdlib.h>

// Structure for each node in the queue
typedef struct Node {
    int data;
    struct Node* next;
} Node;

// Structure for the queue itself
typedef struct Queue {
    Node *front, *rear;
    int size;
} Queue;

// Function to create a new node
#endif