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

#define SERVER_FIFO "/tmp/server_fifo"
#define LOG_FILE "server_log.txt"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"

int log_fd; // Global log file descriptor
int num_clients = 0;

void write_log(const char *message) {
    if (log_fd != -1) {
        write(log_fd, message, strlen(message));
        write(log_fd, "\n", 1);
    }
}
void handle_sigint(int sig) {
    write_log("Received SIGINT. Server is shutting down...");
    close(log_fd);
    unlink(SERVER_FIFO);
    exit(0);
}

void handle_sigchld(int sig) {
    // Clean up any terminated child processes
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        num_clients--;
    }
}

void setup_fifo() {
    if (mkfifo(SERVER_FIFO, 0666) == -1) {
        if (errno != EEXIST) {
            write_log("Failed to create FIFO");
            exit(1);
        }
    }
}

/*okay now i should handle commands*/
//STRTOK
void command_help(int client_fd, char *command)
{
    char message[256];
    if (strcmp(command, "help") == 0)
    {
        sprintf(message, "Available commands are:\nhelp, list, readF, writeT, upload, download, archServer, quit, killServer\n");
        write(client_fd, message, strlen(message));
    }
    else 
    {
        char *token = strtok(command, " ");
        if(token != NULL)
        {
            if (strcmp(token, "readF") == 0)
            {
                sprintf(message, "readF <file> <line #>\nDisplay the #th line of the <file>, returns with an error if <file> does not exist.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "list") == 0)
            {
                sprintf(message, "list\nLists all the files in the current directory.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "writeT") == 0)
            {
                sprintf(message, "writeT <file> <line #> <text>\nWrites <text> to the #th line of the <file>, creates the file if it does not exist.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "upload") == 0)
            {
                sprintf(message, "upload <file>\nUploads the specified <file> to the server.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "download") == 0)
            {
                sprintf(message, "download <file>\nDownloads the specified <file> from the server.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "archServer") == 0)
            {
                sprintf(message, "archServer\nArchives the server.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "quit") == 0)
            {
                sprintf(message, "quit\nQuits the application.\n");
                write(client_fd, message, strlen(message));
            }
            else if (strcmp(token, "killServer") == 0)
            {
                sprintf(message, "killServer\nKills the server process.\n");
                write(client_fd, message, strlen(message));
            }
            else 
            {
                sprintf(message, "Invalid command.\n");
                write(client_fd, message, strlen(message));
            }
        }
    }
}
// STRTOK
void comments(char *buffer, int client_fd)
{
    // Get the command name
    char *token = strtok(buffer, " ");
    if(token != NULL)
    {
        if (strcmp(token, "help") == 0)
        {
            // Pass the rest of the command to the command_help function
            command_help(client_fd, buffer);
        }
        else if (strcmp(token, "list") == 0)
        {
            // Call your function to handle the "list" command here
        }
        else if (strcmp(token, "readF") == 0)
        {
            // Call your function to handle the "readF" command here
        }
        // Add else if branches here for other commands
        // ...
        else 
        {
            char message[] = "Invalid command.\n";
            write(client_fd, message, sizeof(message));
        }
    }
}
void serve_client(int client_fd , int server_fifo_fd) {
    // Send a message to the client

    // Buffer to hold the client's commands
    char buffer[256];
    // Loop that reads commands from the clien
        // Read a command from the client
        if (read(server_fifo_fd, buffer, sizeof(buffer)) > 0) {
            // Process the command
            printf("Received command: %s\n", buffer);
            if(strcmp(buffer, "exit") == 0) {
                close(client_fd);
                return;
            }
            comments(buffer, client_fd);
        }
    printf("Client disconnected.\n");
}
void handle_client(int client_fd, int server_fifo_fd, char *request_type , int max_number_of_clients, int *client_fds) {
    if (strcmp(request_type, "Connect") == 0) {
        // Handle "Connect" request
        printf("CONNECT\n");
        if (num_clients < max_number_of_clients) {
            // Accept the client and fork a new process to handle it
            pid_t pid = fork();
            if (pid == 0) {
                // Child process
                serve_client(client_fd , server_fifo_fd);
                exit(EXIT_SUCCESS);
            } else if (pid > 0) {
                num_clients++;
                // Parent process
                // Continue accepting new clients
            } else {
                // Fork failed
                perror("fork");
                exit(EXIT_FAILURE);
            }
        } else {
            // Make the client wait until a spot becomes available
            // TODO: Implement waiting mechanism
            printf("Queue is full. CONNECT\n");
        }
    } else if (strcmp(request_type, "tryConnect") == 0) {
        // Handle "tryConnect" request
        printf("ICERDEYIM\n");
        if (num_clients < max_number_of_clients) {
            // Accept the client and fork a new process to handle it
            pid_t pid = fork();
            if (pid == 0) {
                // Child process
                serve_client(client_fd , server_fifo_fd);
                exit(EXIT_SUCCESS);
            } else if (pid > 0) {
                // Parent process
                num_clients++;
                // Continue accepting new clients
            } else {
                // Fork failed
                perror("fork");
                exit(EXIT_FAILURE);
            }
        } else {
            // Inform the client that the queue is full
            printf("Queue is full. TRYCONNECT\n");
            // TODO: Implement mechanism to inform client
        }
        }
        else 
        {
            // Invalid request type
            // printf("Invalid request type: %s\n", request_type);
            fprintf(stderr, "Invalid request type: %s\n", request_type);
        }
    }

void accept_client(int client_fd, int *client_fds, int max_number_of_clients) {
    // Read the client's request from the server FIFO
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (read(server_fifo_fd, buffer, sizeof(buffer)) > 0) {
        // Parse the client's PID, server's PID and request type from the buffer
        long client_pid;
        long server_pid;
        char request_type[32];
        printf("BUFFER = %s\n", buffer);
        char *token = strtok(buffer, ":");
        printf("TOKEN = %s\n", token);
        while (token != NULL) {
            sscanf(token, "%ld,%ld,%s", &client_pid, &server_pid, request_type);
            printf("Received request from client %ld: %s\n", client_pid, request_type);

            // Check if the server's PID in the request matches the actual PID of the server
            printf("Server PID: %d\n", getpid());
            if (server_pid != getpid()) {
                fprintf(stderr, "Server PID in the request does not match the actual PID of the server.\n");
                return;
            }

            // Create a new FIFO for this client
            char client_fifo_path[256];
            sprintf(client_fifo_path, CLIENT_FIFO_NAME, client_pid);
            mkfifo(client_fifo_path, 0666);

            // Open the client FIFO for writing
            int client_fd = open(client_fifo_path, O_WRONLY);
            if (client_fd == -1) {
                perror("open client fifo");
                exit(EXIT_FAILURE);
            }

            // Store the client file descriptor
            client_fds[num_clients++] = client_fd;

            // Fork a new process to handle the client
            pid_t pid = fork();
            if (pid == 0) {
                // Child process
                handle_client(client_fd, server_fifo_fd, request_type , max_number_of_clients, client_fds);
                exit(EXIT_SUCCESS);
            } else if (pid > 0) {
                // Parent process
                // Continue accepting new clients
            } else {
                // Fork failed
                perror("fork");
                exit(EXIT_FAILURE);
            }

            token = strtok(NULL, ":");
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
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // Handle SIGCHLD
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }


    // Directory setup
    if (mkdir(dir_name, 0777) == -1) {
        if (errno != EEXIST) {
            perror("Error creating directory");
            return 1;
        }
    }

    if (chdir(dir_name) == -1) {
        perror("Failed to change directory");
        exit(1);
    }

    log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd == -1) {
        perror("Failed to open log file");
        exit(1);
    }

    char log_entry[100];
    sprintf(log_entry, "Server started. PID: %d", getpid());
    write_log(log_entry);

    setup_fifo();

    printf("Server started with PID %d...\n", getpid());
    printf("Waiting for clients...\n");
    int *client_fds  = calloc(max_number_of_clients,sizeof(int));
    // Array to store client file descriptors
    
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (server_fifo_fd == -1) {
        write_log("Failed to open server FIFO");
        exit(1);
    }
    while (1) {
        accept_client(server_fifo_fd, client_fds, max_number_of_clients);
    }

    close(log_fd);
    free(client_fds);
    close(server_fifo_fd);
    unlink(SERVER_FIFO);    
    return 0;
}