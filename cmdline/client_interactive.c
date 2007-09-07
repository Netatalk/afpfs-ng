/* 
	Copyright (C) 1987-2002 Free Software Foundation, Inc.
	portions Copyright (C) 2007 Alex deVries
	
	This is based on readline's filemap.c example, which is very useful.

*/

#include <config.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <stdarg.h>
#include "afp.h"
#include "afp_protocol.h"
#include "client_url.h"
#include "libafpclient_internal.h"
#include "server.h"

static unsigned int uam_mask;
static struct client client;
static char username[AFP_MAX_USERNAME_LEN];
static char password[AFP_MAX_PASSWORD_LEN];



static cmdline_unmount_volume(struct afp_volume * volume) 
{

	return 0;
}

static void cmdline_add_fd(int sock)
{
	return;
}


static void cmdline_log_for_client(struct client * c,
	enum loglevels loglevel, int logtype, char *message, ...)
{
	va_list args;
	char toprint[1024];
	char new_message[1024];

	va_start(args, message);
	vsnprintf(new_message,1024,message,args);
	va_end(args);


	snprintf(toprint,1024, new_message);
	/* Finished with args for now */
	va_end(args);
	printf("%s\n",toprint);
}


static int com_help(char *);

/* A structure which contains information on the commands this program
   can understand. */

typedef struct {
  char *name;			/* User printable name of the function. */
  rl_icpfunc_t *func;		/* Function to call to do the job. */
  char *doc;			/* Documentation for this function.  */
} COMMAND;



/* When non-zero, this global means the user is done using this program. */
static int done=0;


/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *
stripwhite (string)
     char *string;
{
  char *s, *t;

  for (s = string; whitespace (*s); s++)
    ;
    
  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && whitespace (*t))
    t--;
  *++t = '\0';

  return s;
}

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */

static char *command_generator PARAMS((const char *, int));

/* Attempt to complete on the contents of TEXT.  START and END bound the
   region of rl_line_buffer that contains the word to complete.  TEXT is
   the word to complete.  We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing.  Return the array of matches,
   or NULL if there aren't any. */
static char ** fileman_completion (const char *text, 
	int start, int end)
{
	char **matches = NULL;

	/* If this word is at the start of the line, then it is a command
	to complete.  Otherwise it is the name of a file in the current
	directory. */
	if (start == 0)
	matches = rl_completion_matches (text, command_generator);

	return (matches);
}

/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on filenames
   if not. */
static void initialize_readline ()
{
	  /* Allow conditional parsing of the ~/.inputrc file. */
	  rl_readline_name = "afpfsd";

	  /* Tell the completer that we want a crack first. */
	  rl_attempted_completion_function = fileman_completion;
}


/* Return non-zero if ARG is a valid argument for CALLER, else print
   an error message and return zero. */
static int valid_argument (char *caller, char *arg)
{
	if (!arg || !*arg) {
		fprintf (stderr, "%s: Argument required.\n", caller);
		return (0);
	}

	return (1);
}


/* List the file(s) named in arg. */
static int com_list (char * arg)
{
	if (!arg)
		arg = "";
	return 0;
}

static struct afp_url url;

static int client_open(const char *hostname,const char * volume, 
	const char * filename, unsigned int mode, unsigned int * fd)
{
	return 0;
}

static int com_get (char *filename)
{
	unsigned int fd;

	printf("Getting file %s\n",filename);

	client_open(url.hostname,url.volume,filename,0,&fd);

	return 0;
}

static int com_view (char * arg)
{
	char syscom[1024];
	if (!valid_argument ("view", arg))
		return 1;

	sprintf (syscom, "more %s", arg);
	return (system (syscom));
}

static int com_rename (char * arg)
{
  return (1);
}

static int com_stat (char *arg)
{	
	return (0);
}

static int com_delete (char *arg)
{
	return (1);
}


static struct afp_server * server = NULL;

static int com_connect(char * arg)
{
	struct sockaddr_in address;
	char hostname[AFP_HOSTNAME_LEN];
        char volumename[AFP_VOLUME_NAME_LEN];
	unsigned char requested_version;
	unsigned char versions[SERVER_MAX_VERSIONS];
#define BUFFER_SIZE 2048
	char mesg[1024];
	int len=0;
	struct afp_connection_request conn_req;

	if (sscanf(arg, "%s %s",&hostname, &volumename) !=2) {
		printf("usage: <servername>:<volumename>\n");
		return -1;
	}

        bzero(&conn_req,sizeof(conn_req));

        conn_req.requested_version=22;
        conn_req.uam_mask=default_uams_mask();
        bcopy(&username,&conn_req.username,AFP_MAX_USERNAME_LEN);
        bcopy(&password,&conn_req.password,AFP_MAX_PASSWORD_LEN);
        bcopy(&hostname,&conn_req.hostname,255);
        conn_req.port=548;

	if ((server=afp_server_full_connect(&client,&conn_req))==NULL) {
		goto error;
	}

        printf("Connected!\n");
#if 0
	get_address(&client,hostname,548,&address);
	requested_version=22;
	memset(&versions,0,SERVER_MAX_VERSIONS);
	versions[0]=22;

printf("0.\n");
	server=new_server(&client,&address,&versions,
		uam_mask,username,password,requested_version,uam_mask);
printf("1.\n");



printf("1. init\n");
	server = afp_server_init(&address);

	server->incoming_buffer=malloc(BUFFER_SIZE);
	server->bufsize=BUFFER_SIZE;
	add_server(server);

	

printf("2. setup\n");
	if (afp_server_setup_connection(&client,server,&address)<0) {
		printf("Cannot setup connection\n");
		goto error;
	}

printf("3. login\n");

	afp_server_login(server,mesg,&len);

	server = new_server(&client,&address,&versions,
		get_uam_names_list(), username, password, 
		requested_version, uam_mask);

printf("4. done\n");

	if (!server) {
		printf("Error preparing for connection to server: %s\n",
		strerror(errno));
		goto error;
	}
	if (afp_server_connect(server) !=0) {
		printf(
		"Could not connect to server: %s\n",
		strerror(errno));
		goto error;
	}

	dsi_opensession(server);
#endif

	return 0;
error:
	return 1;
}


static int com_pass(char * arg)
{
	if (strlen(arg)==0) {
		printf("You must specify a password\n");
		return -1;
	}

	strncpy(url.password,arg,AFP_MAX_PASSWORD_LEN);

	return 0;

}

static int com_user(char * arg)
{
	if (strlen(arg)==0) {
		printf("You must specify a user\n");
		return -1;
	}

	strncpy(url.username,arg,AFP_MAX_USERNAME_LEN);

	return 0;

}

/* Change to the directory ARG. */
static int com_cd (char *arg)
{
	
	/* To change directory, get a file list and grab the did. */
	return (0);
}

/* Print out the current working directory. */
static int com_pwd (char * ignore)
{
	return 0;
}

/* The user wishes to quit using this program.  Just set DONE non-zero. */
static int com_quit (char *arg)
{
	done = 1;
	return (0);
}



COMMAND commands[] = {
  { "connect", com_connect, "Connect to URL"},
  { "user", com_user, "Set user to USER" },
  { "pass", com_pass, "Set password to PASS" },
  { "cd", com_cd, "Change to directory DIR" },
  { "delete", com_delete, "Delete FILE" },
  { "help", com_help, "Display this text" },
  { "?", com_help, "Synonym for `help'" },
  { "list", com_list, "List files in DIR" },
  { "ls", com_list, "Synonym for `list'" },
  { "pwd", com_pwd, "Print the current working directory" },
  { "quit", com_quit, "Quit" },
  { "rename", com_rename, "Rename FILE to NEWNAME" },
  { "stat", com_stat, "Print out statistics on FILE" },
  { "view", com_view, "View the contents of FILE" },
  { "get", com_get, "Retrieve the file FILENAME and store them locally" },
  { (char *)NULL, (rl_icpfunc_t *)NULL, (char *)NULL }
};

/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
static char * command_generator (const char *text, int state)
{
	static int list_index, len;
	char *name;

	/* If this is a new word to complete, initialize now.  This includes
	saving the length of TEXT for efficiency, and initializing the index
	variable to 0. */
	if (!state) {
		list_index = 0;
		len = strlen (text);
	}

	/* Return the next name which partially matches from the command list. */
	while ((name = commands[list_index].name))
	{
		list_index++;

		if (strncmp (name, text, len) == 0)
			{
			  char *r;

			  r = malloc (strlen (name) + 1);
			  strcpy (r, name);
			  return (r);
			}
	}

	/* If no names matched, then return NULL. */
	return ((char *)NULL);
}

/* Print out help for ARG, or for all of the commands if ARG is
   not present. */
static int com_help (char *arg)
{
  register int i;
  int printed = 0;

  for (i = 0; commands[i].name; i++)
    {
      if (!*arg || (strcmp (arg, commands[i].name) == 0))
        {
          printf ("%s\t\t%s.\n", commands[i].name, commands[i].doc);
          printed++;
        }
    }

  if (!printed)
    {
      printf ("No commands match `%s'.  Possibilties are:\n", arg);

      for (i = 0; commands[i].name; i++)
        {
          /* Print in six columns. */
          if (printed == 6)
            {
              printed = 0;
              printf ("\n");
            }

          printf ("%s\t", commands[i].name);
          printed++;
        }

      if (printed)
        printf ("\n");
    }
  return (0);
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
static COMMAND * find_command (char *name)
{
	  int i;

	  for (i = 0; commands[i].name; i++)
	  	if (strcmp (name, commands[i].name) == 0)
			return (&commands[i]);

	  return ((COMMAND *)NULL);
}

/* Execute a command line. */
static int execute_line (char * line)
{
	int i;
	COMMAND *command;
	char *word;

	/* Isolate the command word. */
	i = 0;
	while (line[i] && whitespace (line[i]))
		i++;
	word = line + i;

	while (line[i] && !whitespace (line[i]))
		i++;

	if (line[i])
		line[i++] = '\0';

	command = find_command (word);

	if (!command) {
		fprintf (stderr, "%s: No such command.\n", word);
		return (-1);
	}

	/* Get argument to command, if any. */
	while (whitespace (line[i]))
		i++;

	word = line + i;

	/* Call the function. */
	return ((*(command->func)) (word));
}


int cmdline_process_client_fds(fd_set * set, int max_fd, int ** onfd)
{

        struct client * c;

        for (c=client_base;c;c=c->next) {
                if (FD_ISSET(c->fd,set)) {
                        if (process_command(c)<0) return -1;
                        return 1;
                }
        }
        return 0;

}



int main(int argc, char *argv[]) 
{
	char *line, *s;

	uam_mask=default_uams_mask();

	libafpclient.handle_command_fd=&cmdline_process_client_fds;
	libafpclient.unmount_volume=&use_unmount_volume;
	libafpclient.log_for_client=&fuse_log_for_client;
	libafpclient.forced_ending_hook=&fuse_forced_ending_hook;
	libafpclient.add_client=&fuse_add_client;
	libafpclient.signal_main_thread=&fuse_signal_main_thread;

		&cmdline_unmount_volume,&cmdline_log_for_client,

	if (init_uams()<0) return -1;

	initialize_readline ();	/* Bind our completer. */

	afp_main_loop();

#if 0
	/* Loop reading and executing lines until the user quits. */
	for ( ; done == 0; ) {
		line = readline ("afp_client: ");

		if (!line) break;

		/* Remove leading and trailing whitespace from the line.
		Then, if there is anything left, add it to the history list
		and execute it. */
		s = stripwhite (line);

		if (*s) {
			add_history (s);
			execute_line (s);
		}

		free (line);
	}
#endif
	exit (0);
}


