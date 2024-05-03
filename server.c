#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include "queue.h"
#define SERVER_FIFO "/tmp/server_fifo"
#define LOG_FILE "server_log.txt"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"
#define CLIENT_FIFO_COMMANDS "/tmp/client_fifo_write_%ld"

int log_fd; // Global log file descriptor
int num_clients = 0;

void write_log(const char *message)
{
    if (log_fd != -1)
    {
        write(log_fd, message, strlen(message));
        write(log_fd, "\n", 1);
    }
}
void handle_sigint(int sig)
{
    write_log("Received SIGINT. Server is shutting down...");
    close(log_fd);
    unlink(SERVER_FIFO);
    exit(0);
}

void handle_sigchld(int sig)
{
    // Clean up any terminated child processes
    int a = 0;
    while ((a = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        printf("Child process %d terminated\n", a);
        num_clients--;
    }
}

void setup_fifo()
{
    if (mkfifo(SERVER_FIFO, 0666) == -1)
    {
        if (errno != EEXIST)
        {
            write_log("Failed to create FIFO");
            exit(1);
        }
    }
}
/*okay now i should handle commands*/
// STRTOK
void list(int client_fd_write)
{
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            write(client_fd_write, dir->d_name, strlen(dir->d_name));
            write(client_fd_write, "\n", 1);
        }
        closedir(d);
    }
}
void command_help(int client_fd_write, char *command)
{
    char message[256];
    printf("COMMAND = %sada\n", command);
    if (strcmp(command, "help") == 0)
    {
        sprintf(message, "Available commands are:\nhelp, list, readF, writeT, upload, download, archServer, quit, killServer\n");
        write(client_fd_write, message, strlen(message));
    }
    else
    {
        char *token = strchr(command, ' ');
        token = token + 1;
        printf("TOKENINLASTFUNC = %sada\n", token);
        if (token != NULL)
        {
            if (strcmp(token, "readF") == 0)
            {
                sprintf(message, "readF <file> <line #>\nDisplay the #th line of the <file>, returns with an error if <file> does not exist.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "list") == 0)
            {
                sprintf(message, "list\nLists all the files in the current directory.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "writeT") == 0)
            {
                sprintf(message, "writeT <file> <line #> <text>\nWrites <text> to the #th line of the <file>, creates the file if it does not exist.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "upload") == 0)
            {
                sprintf(message, "upload <file>\nUploads the specified <file> to the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "download") == 0)
            {
                sprintf(message, "download <file>\nDownloads the specified <file> from the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "archServer") == 0)
            {
                sprintf(message, "archServer\nArchives the server.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "quit") == 0)
            {
                sprintf(message, "quit\nQuits the application.\n");
                write(client_fd_write, message, strlen(message));
            }
            else if (strcmp(token, "killServer") == 0)
            {
                sprintf(message, "killServer\nKills the server process.\n");
                write(client_fd_write, message, strlen(message));
            }
            else
            {
                sprintf(message, "Invalid command.\n");
                write(client_fd_write, message, strlen(message));
            }
        }
    }
}
// STRTOK
void write_to_file(const char *filename, const char *content) {
    // Open the file with write mode, creating if it doesn't exist, and append at the end
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
        perror("open");
        return;
    }

    // Write content to the file
    if (write(fd, content, strlen(content)) == -1) {
        perror("write");
    }

    // Append newline if necessary
    if (content[strlen(content) - 1] != '\n') {
        if (write(fd, "\n", 1) == -1) {
            perror("write");
        }
    }

    close(fd);
}
void comments(char *buffer, int client_fd_write)
{
    // Get the command name
    char temp[strlen(buffer) + 1];
    strcpy(temp, buffer);
    char *token = strtok(temp, " ");
    printf("TOKEN = %sada\n", token);
    printf("temp = %sada\n", temp);
    printf("BUFFETWITHTOKEN = %sada\n", buffer);
    if (token != NULL)
    {
        if (strcmp(token, "help") == 0)
        {
            // Pass the rest of the command to the command_help function
            command_help(client_fd_write, buffer);
        }
        else if (strcmp(token, "list") == 0)
        {
            // Call your function to handle the "list" command here
            list(client_fd_write);
        }
        else if (strcmp(token, "readF") == 0)
        {
            // Call your function to handle the "readF" command here
        }
        else if (strcmp(token, "writeT") == 0)
        {
            char *filename = strtok(NULL, " ");
            printf("FILENAME = %s\n", filename);
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return;
            }

            char *line_number_str = strtok(NULL, " ");
            int line_number = line_number_str != NULL ? atoi(line_number_str) : -1;
            printf("LINE NUMBER = %d\n", line_number);
            char *content = strtok(NULL, "\n");
            if (content == NULL)
            {
                char message[] = "Missing content to write.\n";
                write(client_fd_write, message, sizeof(message));
                return;
            }
            printf("CONTENT = %s\n", content);
            write_to_file(filename, content);
            write(client_fd_write, "Content written to file.\n", 26);
        }
        else if (strcmp(token, "upload") == 0)
        {
            // Call your function to handle the "upload" command here
        }
        else if (strcmp(token, "download") == 0)
        {
            // Call your function to handle the "download" command here
        }
        else if (strcmp(token, "archServer") == 0)
        {
            // Call your function to handle the "archServer" command here
        }
        else if (strcmp(token, "quit") == 0)
        {
            // Call your function to handle the "quit" command here
        }
        else if (strcmp(token, "killServer") == 0)
        {
            // Call your function to handle the "killServer" command here
        }
        else
        {
            char message[] = "Invalid command.\n";
            write(client_fd_write, message, sizeof(message));
        }
}}
/*okay now i should handle commands*/

void serve_client(int client_fd_write, int client_fd_read)
{
    // Send a message to the client

    // Buffer to hold the client's commands
    printf("Client connected\n");
    char buffer[256];
    // Loop that reads commands from the clien
    // Read a command from the client
    while (1)
    {
        printf("while a girdim.\n");
        if (read(client_fd_read, buffer, sizeof(buffer)) > 0)
        {
            // Process the command
            printf("Received command: %s\n", buffer);
            if (strcmp(buffer, "exit") == 0)
            {
                close(client_fd_write);
                break;
            }
            comments(buffer, client_fd_write);
            memset(buffer, 0, sizeof(buffer));
        }
        else
        {
            printf("Client disconnected EXIT\n");
            break;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    close(client_fd_write);
    close(client_fd_read);
    unlink(CLIENT_FIFO_COMMANDS);
    unlink(CLIENT_FIFO_NAME);
    printf("Client disconnected\n");
}
int handle_client(int client_fd_write, int client_fd_read, char *request_type, int max_number_of_clients, int *client_fd_writes)
{
    if (strcmp(request_type, "Connect") == 0)
    {
        // Handle "Connect" request
        if (num_clients < max_number_of_clients)
        {
            serve_client(client_fd_write, client_fd_read);
            return 1;
        }
        else
        {
            // Make the client wait until a spot becomes available
            // TODO: Implement waiting mechanism
            printf("Queue is full. CONNECT\n");
            return 0;
        }
    }
    else if (strcmp(request_type, "tryConnect") == 0)
    {
        // Handle "tryConnect" request
        if (num_clients < max_number_of_clients)
        {
            // Accept the client and fork a new process to handle it
            // Child process
            serve_client(client_fd_write, client_fd_read);
            return 1;
        }
        else
        {
            // Inform the client that the queue is full
            printf("Queue is full. TRYCONNECT\n");
            return 0;
            // TODO: Implement mechanism to inform client
        }
    }
    else
    {
        // Invalid request type
        // printf("Invalid request type: %s\n", request_type);
        fprintf(stderr, "Invalid request type: %s\n", request_type);
        return 0;
    }
}
void accept_client(int client_fd_write, int *client_fd_writes, int max_number_of_clients, Queue *client_queue) {
    // Read the client's request from the server FIFO
    char buffer[256] = {0};
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (read(server_fifo_fd, buffer, sizeof(buffer)) > 0) {
        // Parse the client's PID, server's PID, and request type from the buffer
        long client_pid;
        long server_pid;
        char request_type[32];
        printf("BUFFER = %s\n", buffer);
        char *token = strtok(buffer, ":");
        printf("TOKEN = %s\n", token);
        while (token != NULL) {
            sscanf(token, "%ld,%ld,%s:", &client_pid, &server_pid, request_type);
            printf("Received request from client %ld: %s\n", client_pid, request_type);
            printf("Server PID: %ld\n", server_pid);
            // Check if the server's PID in the request matches the actual PID of the server
            if (server_pid != getpid()) {
                fprintf(stderr, "Server PID in the request does not match the actual PID of the server.\n");
                return;
            }

            // Create a new FIFO for this client
            char client_fifo_write[256] = {0};
            char client_fifo_read[256] = {0};
            sprintf(client_fifo_write, CLIENT_FIFO_NAME, client_pid);
            mkfifo(client_fifo_write, 0666);
            sprintf(client_fifo_read, CLIENT_FIFO_COMMANDS, client_pid);
            mkfifo(client_fifo_read, 0666);
            // Open the client FIFO for writing
            int client_fd_write = open(client_fifo_write, O_WRONLY);
            if (client_fd_write == -1) {
                perror("open client fifo");
                exit(EXIT_FAILURE);
            }
            int client_fd_read = open(client_fifo_read, O_RDONLY);
            // Store the client file descriptor
            if (client_fd_read == -1) {
                perror("open client fifo");
                exit(EXIT_FAILURE);
            }

            // Check the request type
            if (strcmp(request_type, "Connect") == 0) {
                // Handle "Connect" request
                if (num_clients < max_number_of_clients) {
                    // Accept the client and fork a new process to handle it
                    // Child process
                    serve_client(client_fd_write, client_fd_read);
                    pid_t pid = fork();
                    if (pid == 0) {
                        // Child process
                        handle_client(client_fd_write, client_fd_read, request_type, max_number_of_clients, client_fd_writes);
                        exit(EXIT_SUCCESS);
                    } else if (pid > 0) {
                        // Parent process
                        client_fd_writes[num_clients] = client_fd_write;
                        num_clients++;
                        printf("Num clients after forking in parent process = %d\n", num_clients);
                        // Continue accepting new clients
                    } else {
                        // Fork failed
                        perror("fork");
                        exit(EXIT_FAILURE);
                    }
                } else {
                    // Queue is full, inform the client to wait
                    printf("Queue is full. Client %ld is waiting for a spot.\n", client_pid);
                    // Add client to the queue
                    client_queue->enqueue(client_queue, client_pid);
                    // Inform client to wait
                    char message[256];
                    sprintf(message, "Queue is full. Please wait for a spot to become available. Your position in the queue is %d.\n", client_queue->size);
                    write(client_fd_write, message, strlen(message));
                }
            } else if (strcmp(request_type, "tryConnect") == 0) {
                // Handle "tryConnect" request
                if (num_clients < max_number_of_clients) {
                    // Accept the client and fork a new process to handle it
                    // Child process
                    serve_client(client_fd_write, client_fd_read);
                    pid_t pid = fork();
                    if (pid == 0) {
                        // Child process
                        handle_client(client_fd_write, client_fd_read, request_type, max_number_of_clients, client_fd_writes);
                        exit(EXIT_SUCCESS);
                    } else if (pid > 0) {
                        // Parent process
                        client_fd_writes[num_clients] = client_fd_write;
                        num_clients++;
                        printf("Num clients after forking in parent process = %d\n", num_clients);
                        // Continue accepting new clients
                    } else {
                        // Fork failed
                        perror("fork");
                        exit(EXIT_FAILURE);
                    }
                } else {
                    // Queue is full, inform the client and let it leave without waiting
                    printf("Queue is full. Client %ld leaving without waiting.\n", client_pid);
                    // Inform client to leave without waiting
                    char message[256] = "Queue is full. Please try again later.\n";
                    write(client_fd_write, message, strlen(message));
                }
            } else {
                // Invalid request type
                fprintf(stderr, "Invalid request type: %s\n", request_type);
                // Close file descriptors and clean up
                close(client_fd_write);
                close(client_fd_read);
                return;
            }

            token = strtok(NULL, ":");
        }
    }

    // After serving a client, check if there are clients waiting in the queue
    if (!isEmpty(client_queue)) {
        // Dequeue the first client from the queue
        long queued_client_pid = client_queue->dequeue(client_queue);

        // Create FIFO names for the dequeued client
        char queued_client_fifo_write[256] = {0};
        char queued_client_fifo_read[256] = {0};
        sprintf(queued_client_fifo_write, CLIENT_FIFO_NAME, queued_client_pid);
        sprintf(queued_client_fifo_read, CLIENT_FIFO_COMMANDS, queued_client_pid);

        // Open the client FIFOs for writing and reading
        int queued_client_fd_write = open(queued_client_fifo_write, O_WRONLY);
        int queued_client_fd_read = open(queued_client_fifo_read, O_RDONLY);

        // Serve the dequeued client
        serve_client(queued_client_fd_write, queued_client_fd_read);

        // Fork a new process to handle the client
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            handle_client(queued_client_fd_write, queued_client_fd_read, "Connect", max_number_of_clients, client_fd_writes);
            exit(EXIT_SUCCESS);
        } else if (pid > 0) {
            // Parent process
            client_fd_writes[num_clients] = queued_client_fd_write;
            num_clients++;
            printf("Num clients after forking in parent process = %d\n", num_clients);
            // Continue accepting new clients
        } else {
            // Fork failed
            perror("fork");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <dirname> <max.#ofClients>\n", argv[0]);
        return 1;
    }
    int max_number_of_clients = atoi(argv[2]);
    char *dir_name = argv[1];

    struct sigaction sa;

    // Handle SIGINT
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart functions if interrupted by handler
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    // Handle SIGCHLD
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // Directory setup
    if (mkdir(dir_name, 0777) == -1)
    {
        if (errno != EEXIST)
        {
            perror("Error creating directory");
            return 1;
        }
    }

    if (chdir(dir_name) == -1)
    {
        perror("Failed to change directory");
        exit(1);
    }

    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd == -1)
    {
        perror("Failed to open log file");
        exit(1);
    }

    char log_entry[100];
    sprintf(log_entry, "Server started. PID: %d", getpid());
    write_log(log_entry);

    setup_fifo();

    printf("Server started with PID %d...\n", getpid());
    printf("Waiting for clients...\n");
    int *client_fd_writes = calloc(max_number_of_clients, sizeof(int));
    // Array to store client file descriptors
    Queue *client_queue = createQueue();
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (server_fifo_fd == -1)
    {
        write_log("Failed to open server FIFO");
        exit(1);
    }
    printf("Accepting client...\n");

    while (1)
        accept_client(server_fifo_fd, client_fd_writes, max_number_of_clients , client_queue);

    close(log_fd);
    free(client_fd_writes);
    close(server_fifo_fd);
    unlink(SERVER_FIFO);
    return 0;
}