#include <stdio.h>
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
#include "queue_func.c"
#define SERVER_FIFO "/tmp/server_fifo"
#define LOG_FILE "server_log.txt"
#define CLIENT_FIFO_NAME "/tmp/client_fifo_%ld"
#define CLIENT_FIFO_COMMANDS "/tmp/client_fifo_write_%ld"
#define DEQUEUE "tmp/dequeue"
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
// catch exit
void sigusr1_handler(int signum)
{
    if (signum == SIGUSR1)
    {
        // Handle client termination
        printf("Received SIGUSR1\n");
        num_clients--; // Decrement the count of active clients
    }
}

void handle_sigchld(int sig)
{
    // Clean up any terminated child processes
    printf("Num clients before = %d\n", num_clients);
    int a = 0;
    while ((a = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        printf("Child process %d terminated\n", a);
        // num_clients--;
    }
    printf("Num clients after = %d\n", num_clients);
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
// STRTOK
int write_to_file(const char *filename, const char *content)
{
    // Open the file with write mode, creating if it doesn't exist, and append at the end
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1)
    {
        perror("open");
        write(fd, "Error opening file.\n", 20);
        return 0;
    }

    // Write content to the file
    if (write(fd, content, strlen(content)) == -1)
    {
        perror("write");
        write(fd, "Error writing content to file.\n", 30);
        return 0;
    }

    // Append newline if necessary
    if (content[strlen(content) - 1] != '\n')
    {
        if (write(fd, "\n", 1) == -1)
        {
            perror("write");
            write(fd, "Error writing newline character.\n", 31);
            return 0;
        }
    }

    close(fd);
    return 1;
}
int readF(int client_fd_write, char *buffer)
{
    char *filename = strtok(NULL, " ");
    if (filename == NULL)
    {
        char message[] = "Missing file name.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }

    char *line_number_str = strtok(NULL, " ");
    int line_number = line_number_str != NULL ? atoi(line_number_str) : -1;
    printf("line number = %d\n", line_number);
    int file = open(filename, O_RDONLY);
    if (file < 0)
    {
        char message[] = "Could not open file.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }
    char line[256] = {0};
    int current_line_number = 1;
    char *file_contents = NULL;
    size_t file_size = 0;

    if (line_number == -1)
    {
        // Count the number of bytes in the file
        char ch;
        while (read(file, &ch, 1) > 0)
        {
            file_size++;
        }

        // Allocate an array of the appropriate size
        file_contents = malloc(file_size + 1); // +1 for the null terminator

        // Go back to the beginning of the file
        lseek(file, 0, SEEK_SET);

        // Read the entire file into the array
        read(file, file_contents, file_size);

        // Null-terminate the string
        file_contents[file_size] = '\0';
    }
    else
    {
        // Read the specified line
        ssize_t n;
        while ((n = read(file, line, sizeof(line) - 1)) > 0)
        {
            line[n] = '\0'; // Null-terminate the string
            if (line_number == current_line_number)
            {
                write(client_fd_write, line, n);
                break;
            }
            current_line_number++;
            memset(line, 0, sizeof(line));
        }
    }

    close(file);

    if (file_contents != NULL)
    {
        // how can i write an integer
        //  char str[12];
        //  sprintf(str,"%d",(int)file_size);
        //  printf("%s",str);
        printf("%s\n", file_contents);
        //  write(client_fd_write, str, sizeof(str));
        //  Write the entire file to the client
        printf("file_size = %d\n", file_size);
        write(client_fd_write, file_contents, sizeof(file_contents));
        free(file_contents);
    }
    return 1;
}

int upload_file(int client_fd_write, char *filename)
{
    // Open the source file in the client's directory
    char src_path[256];
    sprintf(src_path, "Client_%d/%s", getpid(), filename);
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1)
    {
        perror("Could not open source file");
        write(client_fd_write, "Could not open source file.", 27);
        return 0;
    }

    // Open the destination file in the server's directory
    int dest_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("Could not open destination file");
        close(src_fd);
        write(client_fd_write, "Could not open destination file.", 32);
        return 0;
    }

    // Read the source file byte by byte and write it to the destination file
    char byte;
    ssize_t bytes_read;
    int counter = 0;
    while ((bytes_read = read(src_fd, &byte, 1)) > 0)
    {
        if (write(dest_fd, &byte, 1) != 1)
        {
            perror("Write error");
            write(client_fd_write, "Write error.", 12);
            close(src_fd);
            close(dest_fd);
            return 0;
        }
        ++counter;
    }
    printf("Uploaded %d bytes\n", counter);
    // Check if read error occurred
    if (bytes_read == -1)
    {
        perror("Read error");
        write(client_fd_write, "Read error.", 11);
        close(src_fd);
        close(dest_fd);
        return 0;
    }

    // Close the file descriptors
    close(src_fd);
    close(dest_fd);

    write(client_fd_write, "File uploaded successfully.", 27);
    return 1;
}
int download_file(int client_fd_write, char *filename)
{
    // Open the source file in the server's directory
    printf("filename = %s\n", filename);
    int src_fd = open(filename, O_RDONLY);
    if (src_fd == -1)
    {
        perror("Could not open source file");
        write(client_fd_write, "Could not open source file.", 27);
        return 0;
    }

    // Create a directory with the PID of the current process
    char dir_name[256];
    sprintf(dir_name, "Client_%d", getpid());

    // Open the destination file in the client's directory
    char dest_path[256];
    sprintf(dest_path, "%s/%s", dir_name, filename);
    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("Could not open destination file");
        close(src_fd);
        write(client_fd_write, "Could not open destination file.", 32);
        return 0;
    }

    // Read the source file byte by byte and write it to the destination file
    char byte;
    ssize_t bytes_read;
    int counter = 0;
    while ((bytes_read = read(src_fd, &byte, 1)) > 0)
    {
        if (write(dest_fd, &byte, 1) != 1)
        {
            perror("Write error");
            write(client_fd_write, "Write error.", 12);
            close(src_fd);
            close(dest_fd);
            return 0;
        }
        ++counter;
    }
    printf("Downloaded %d bytes\n", counter);
    // Check if read error occurred
    if (bytes_read == -1)
    {
        perror("Read error");
        write(client_fd_write, "Read error.", 11);
        close(src_fd);
        close(dest_fd);
        return 0;
    }

    // Close the file descriptors
    close(src_fd);
    close(dest_fd);

    write(client_fd_write, "File downloaded.", 17);
    return 1;
}

void command_help(int client_fd_write, char *command)
{
    char message[256];
    printf("COMMAND = %sada\n", command);
    if (strcmp(command, "help") == 0)
    {
        printf("neden burdayim\n");
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
int archive_server_files(int client_fd_write, char *filename, char *server_dir_name)
{
    printf("Archiving the current contents of the server...\n");
    write(client_fd_write, "Archiving the current contents of the server...\n", 46);
    char server_dir[50];
    sprintf(server_dir, "%s", server_dir_name);
    // Create a child process
    pid_t pid = fork();

    if (pid < 0)
    {
        // Fork failed
        printf("Fork failed.\n");
        return 0;
    }
    else if (pid == 0)
    {
        // Child process
        printf("Creating archive directory...\n");

        // Call the tar utility to create a tar archive of the server directory
        printf("Calling tar utility... child PID %d\n", getpid());
        execl("/bin/tar", "tar", "-C", server_dir, "-cvf", filename, server_dir_name, NULL);

        // If execlp returns, it means there was an error
        printf("execlp failed.\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        // Parent process
        // Wait for the child process to finish
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            printf("Child returned with SUCCESS.\n");
        }
        else
        {
            printf("Child process failed.\n");
        }
    }

    printf("Copying the archive file...\n");
    // Copy the archive file code here...
    write(client_fd_write, "Copying the archive file...\n", 28);

    printf("Removing archive directory...\n");
    // Remove the archive directory code here...
    write(client_fd_write, "Removing archive directory...\n", 31);
    printf("SUCCESS. Server side files are archived in \"%s\". Download this using download function.\n", filename);
    download_file(client_fd_write, filename);
    write(client_fd_write, "SUCCESS. Server side files are archived. Download this using download function.\n", 76);
}
int comments(char *buffer, int client_fd_write, int server , char* server_dir_name)
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
            return 1;
        }
        else if (strcmp(token, "list") == 0)
        {
            // Call your function to handle the "list" command here
            list(client_fd_write);
            return 1;
        }
        else if (strcmp(token, "readF") == 0)
        {
            // Call your function to handle the "readF" command here
            return readF(client_fd_write, buffer);
        }
        else if (strcmp(token, "writeT") == 0)
        {
            char *filename = strtok(NULL, " ");
            printf("FILENAME = %s\n", filename);
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }

            char *line_number_str = strtok(NULL, " ");
            int line_number = line_number_str != NULL ? atoi(line_number_str) : -1;
            printf("LINE NUMBER = %d\n", line_number);
            char *content = strtok(NULL, "\n");
            if (content == NULL)
            {
                char message[] = "Missing content to write.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            printf("CONTENT = %s\n", content);
            int a = write_to_file(filename, content);
            if (a == 1)
            {
                write(client_fd_write, "Content written to file.\n", 26);
            }
            return a;
        }
        else if (strcmp(token, "upload") == 0)
        {
            char *filename = strtok(NULL, " ");
            printf("FILENAME = %s\n", filename);
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            return upload_file(client_fd_write, filename);
        }
        else if (strcmp(token, "download") == 0)
        {
            // Call your function to handle the "download" command here
            char *filename = strtok(NULL, " ");
            if (filename == NULL)
            {
                char message[] = "Missing file name.\n";
                write(client_fd_write, message, sizeof(message));
                return 0;
            }
            return download_file(client_fd_write, filename);
        }

        else if (strcmp(token, "archServer") == 0)
        {
            char *filename = strtok(NULL, " ");
            char cwd[1024];

            // Get the current working directory
            if (getcwd(cwd, sizeof(cwd)) != NULL)
            {
                // Call your function to handle the "archServer" command
                return archive_server_files(client_fd_write, filename, cwd);
            }
            else
            {
                perror("getcwd() error");
                return -1;
            }
        }
        else if (strcmp(token, "quit") == 0)
        {
            // Call your function to handle the "quit" command here
            return 0;
        }
        else if (strcmp(token, "killServer") == 0)
        {
            // Call your function to handle the "killServer" command here
            write(client_fd_write, "Server is shutting down...", 26);
            kill(server, SIGINT);
            return 1;
        }
        return 0;
    }
    else
    {
        char message[] = "Invalid command.\n";
        write(client_fd_write, message, sizeof(message));
        return 0;
    }
}
/*okay now i should handle commands*/

void serve_client(int client_fd_write, int client_fd_read, int server , char* server_dir_name)
{
    // Send a message to the client

    // Buffer to hold the client's commands
    printf("Client connected\n");
    char buffer[256] = {0};
    char dir_name[256];
    sprintf(dir_name, "Client_%d", getpid());
    mkdir(dir_name, 0755);
    // Loop that reads commands from the clien
    // Read a command from the client
    while (1)
    {
        printf("while a girdim.\n");
        if (read(client_fd_read, buffer, sizeof(buffer)) > 0)
        {
            // Process the command
            printf("Received command: %s\n", buffer);
            if (strcmp(buffer, "quit") == 0)
            {
                close(client_fd_write);
                break;
            }
            if (comments(buffer, client_fd_write, server , server_dir_name) == 0)
                continue;
            memset(buffer, 0, sizeof(buffer));
        }
        else
        {
            printf("Client disconnected EXIT\n");
            break;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    num_clients--;
    close(client_fd_write);
    close(client_fd_read);
    printf("Client disconnected\n");
    kill(getppid(), SIGUSR1);
}
int open_read_fifo(int client_pid)
{
    char client_fifo_read[256] = {0};
    sprintf(client_fifo_read, CLIENT_FIFO_COMMANDS, (long)client_pid);
    mkfifo(client_fifo_read, 0666);
    int client_fd_read = open(client_fifo_read, O_RDONLY);
    // Store the client file descriptor
    if (client_fd_read == -1)
    {
        perror("open client fifo");
        exit(EXIT_FAILURE);
    }
    return client_fd_read;
}
int accept_client(int client_fd_write, int max_number_of_clients, Queue *client_queue, int server , char* server_dir_name)
{
    // Read the client's request from the server FIFO
    struct sigaction sa;
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
    char buffer[256] = {0};
    memset(buffer, 0, sizeof(buffer));
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    if (read(server_fifo_fd, buffer, sizeof(buffer)) > 0)
    {
        // Parse the client's PID, server's PID, and request type from the buffer
        long client_pid;
        long server_pid;
        char request_type[32];
        char *token = strtok(buffer, ":");
        printf("REQUSET RECEIVED\n");
        sscanf(token, "%ld,%ld,%s", &client_pid, &server_pid, request_type);
        printf("Received request from client %ld: %sa\n", client_pid, request_type);
        printf("Server PID: %lda\n", server_pid);
        // Check if the server's PID in the request matches the actual PID of the server
        if ((int)server_pid != (int)server)
        {
            fprintf(stderr, "Server PID in the request does not match the actual PID of the server.\n");
            return 1;
        }
        int client_fd_read;
        // Create a new FIFO for this client
        char client_fifo_write[256] = {0};
        char client_fifo_read[256] = {0};
        sprintf(client_fifo_write, CLIENT_FIFO_NAME, client_pid);
        mkfifo(client_fifo_write, 0666);
        // int client_fd_read;
        if (client_fd_write == -1)
        {
            perror("open client fifo");
            exit(EXIT_FAILURE);
        }
        // Check the request type
        if (strcmp(request_type, "Connect") == 0)
        {
            // Handle "Connect" request
            if (num_clients < max_number_of_clients)
            {
                // Accept the client and fork a new process to handle it
                // Child process
                int client_fd_write = open(client_fifo_write, O_WRONLY);
                client_fd_read = open_read_fifo(client_pid);
                printf("Client connected = %ld , Num_clients = %d\n", client_pid, num_clients);
                num_clients++;
                pid_t pid = fork();
                if (pid == 0)
                {
                    // Child process
                    serve_client(client_fd_write, client_fd_read, server , server_dir_name);
                }
                else if (pid > 0)
                {
                    // Parent process
                    printf("Num clients after forking in parent process = %d\n", num_clients);
                    // Continue accepting new clients
                }
                else
                {
                    // Fork failed
                    perror("fork");
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                // Queue is full, inform the client to wait
                printf("Server is full. Client %ld is waiting for a spot.\n", client_pid);
                // Add client to the queue
                enqueue(client_queue, client_pid);
                // Inform client to wait
                char message[256];
                sprintf(message, "Server is full. Please wait for a spot to become available. Your position in the queue is %d.\n", client_queue->size);
                // write(client_fd_write, message, strlen(message));
                printf("merhaba\n");
            }
        }
        else if (strcmp(request_type, "tryConnect") == 0)
        {
            // Handle "tryConnect" request
            if (num_clients < max_number_of_clients)
            {
                // Accept the client and fork a new process to handle it
                // Child process
                int client_fd_write = open(client_fifo_write, O_WRONLY);
                client_fd_read = open_read_fifo(client_pid);
                printf("Client connected = %ld , Num_clients = %d\n", client_pid, num_clients);
                num_clients++;
                pid_t pid = fork();
                if (pid == 0)
                {
                    // Child process
                    serve_client(client_fd_write, client_fd_read, server , server_dir_name);
                }
                else if (pid > 0)
                {
                    // Parent process
                    printf("Num clients after forking in parent process = %d\n", num_clients);
                    // Continue accepting new clients
                }
                else
                {
                    // Fork failed
                    perror("fork");
                    exit(EXIT_FAILURE);
                }
            }
            else
            { // not working
                // Queue is full, inform the client and let it leave without waiting
                printf("Server is full. Client %ld leaving without waiting.\n", client_pid);
                // Inform client to leave without waiting
                char message[256] = "Server is full. Please try again later.\n";
                write(client_fd_write, message, strlen(message));
                kill(client_pid, SIGTERM);
                // Close file descriptors and clean up
                close(client_fd_write);
                close(client_fd_read);
                unlink(CLIENT_FIFO_COMMANDS);
                unlink(CLIENT_FIFO_NAME);
                return 0;
                // how to kill this process
            }
        }
        else
        {
            // Invalid request type
            fprintf(stderr, "Invalid request type: %s\n", request_type);
            write(client_fd_write, "Invalid request type.\n", 23);
            // Close file descriptors and clean up
            close(client_fd_write);
            close(client_fd_read);
            unlink(CLIENT_FIFO_COMMANDS);
            unlink(CLIENT_FIFO_NAME);
            return 1;
        }
    }

    // After serving a client, check if there are clients waiting in the queue
    if (!isEmpty(client_queue) && num_clients < max_number_of_clients)
    {
        // Dequeue the first client from the queue
        printf("\nQUEUE SIZE = %d\n", client_queue->size);
        long queued_client_pid = dequeue(client_queue);
        printf("\nDequeued client %ld from the queue\n", queued_client_pid);
        // Create FIFO names for the dequeued client
        char queued_client_fifo_write[256] = {0};
        char queued_client_fifo_read[256] = {0};
        sprintf(queued_client_fifo_write, CLIENT_FIFO_NAME, queued_client_pid);
        sprintf(queued_client_fifo_read, CLIENT_FIFO_COMMANDS, queued_client_pid);

        // Open the client FIFOs for writing and reading

        // // Fork a new process to handle the client
        // int queued_client_fd_read = open(queued_client_fifo_read, O_RDONLY);
        num_clients++;
        pid_t pid = fork();
        if (pid == 0)
        {
            // Child process
            int queued_client_fd_write = open(queued_client_fifo_write, O_WRONLY);
            int queued_client_fd_read = open(queued_client_fifo_read, O_RDONLY);
            serve_client(queued_client_fd_write, queued_client_fd_read, server , server_dir_name);
            exit(EXIT_SUCCESS);
        }
        else if (pid > 0)
        {
            // Parent process
            printf("Num clients after forking in parent process = %d\n", num_clients);
            // Continue accepting new clients
        }
        else
        {
            // Fork failed
            perror("fork");
            exit(EXIT_FAILURE);
        }
    }
    return 1;
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

    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
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
    // Array to store client file descriptors
    Queue *client_queue;
    client_queue = createQueue();
    int server_fifo_fd = open(SERVER_FIFO, O_RDONLY);
    int server_pid = getpid();
    if (server_fifo_fd == -1)
    {
        write_log("Failed to open server FIFO");
        exit(1);
    }
    printf("Accepting client...\n");

    while (1)
    {
        accept_client(server_fifo_fd, max_number_of_clients, client_queue, server_pid , dir_name);
        // printf("Num clients = %d\n", num_clients);
    }

    close(log_fd);
    close(server_fifo_fd);
    unlink(SERVER_FIFO);
    destroyQueue(client_queue);
    return 0;
}