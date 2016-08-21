package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"time"
	"../internal"
	"../lib/support/client"
	"../lib/support/rpc"
)

var reader *bufio.Reader

const (
	SIGNUP = "signup"
	LOGIN = "login"
	QUIT = "quit"
	INVALID = "invalid"
	LOGIN_VALID = "valid"
	LOGIN_TIME = "time"
	LOGIN_INCORRECT = "incorrect"
	ILLEGAL_CHARS = ";-/$#.+=*'\""
	MAX_INPUT_LEN = 15
	MIN_INPUT_LEN = 5
	SLEEP_TIME = 10
	INVALID_MSG string = "Invalid login"
	RATE_MSG string = "Have to wait 10 seconds after invalid login to try again"
	MAX_FILE_SIZE_BYTES int = 500000000 				//500mb max file size
)

func main() {
	//client must be passed a port the server is listening on
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %v <server>\n", os.Args[0])
		os.Exit(1)
	}
	// create a server remote to send calls to the server
	server := rpc.NewServerRemote(os.Args[1])
	// create a reader to read user input
	reader = bufio.NewReader(os.Stdin)
	// prompt the user 
	usr, token := PromptUser(server, reader)
	// if the token is actually a quit sign -- exit cleanly
	if strings.Compare(token, QUIT) != 0 {
		// create the client
		c := Client{server, usr, token}
		err := client.RunCLI(&c) 
		if err != nil {
			// don't actually log the error (printed in client.RunCLI)
			os.Exit(1)
		}
	}
}

type Client struct {
	server *rpc.ServerRemote //pointer to server to make calls
	usr string               // client username (id)
	token string             //token to prove authentication
}

/*
Input Values: a server remote and a reader
Return Values: a pair of strings (username, token)
Preconditions: none
Postconditions: a client has been made to connect
with the server or the program has been quit
Behavior: the function gathers user input
until they choose to signup, login or quit the program
Security Assumptions: none
*/
func PromptUser(server *rpc.ServerRemote, reader *bufio.Reader) (string, string) {
	fmt.Println("Welcome to SecureBox!")
	// prompt the user
	response := GatherUserInput(reader)
	// keep trying to get a response unless the user inputs a quit
	for strings.Compare(response, QUIT) != 0 {
		switch response {
			case SIGNUP:
				return PerformSignup(server, reader)
			case LOGIN:
				return EnforceLogin(server, reader)
		}
		response = GatherUserInput(reader)
	}
	return QUIT, QUIT
}

/*
Input Values: a reader to read user input
Return Values: a string which is the trimmed user input
Preconditions: none
Postconditions: none
Behavior: user input is gathered and the input
is cleaned and returned
Security Assumptions: none
*/
func GatherUserInput(reader *bufio.Reader) string {
	fmt.Printf("Would you like to %v, %v or %v? ", SIGNUP, LOGIN, QUIT)
	response, err := GetCleanedInput(reader)
	if err != nil {
		fmt.Println("Error on user input.")
		return INVALID
	}
	return response
}

/*
Input Values: a reader to read user input
Return Values: cleaned user input
Preconditions: none
Postconditions: none
Behavior: the program holds to wait for the user
to type and then the response is trimmed and returned
Security Assumptions: none
*/
func GetCleanedInput(reader *bufio.Reader) (string, error) {
	response, err := reader.ReadString('\n')
	return strings.TrimSpace(response), err
}

/*
Input Values: an input string which is the actual
input, and a category for what type of input it is
Return Values: a boolean on whether or not the input
is allowed
Preconditions: none 
Postconditions: the input string is either approved 
or denied as legal input
Behavior: the input string is checked for its length
and checked to see if it contains illegal characters
Security Assumptions: NOT SURE
*/
func IsValidInput(input string, category string) bool {
	if len(input) > MAX_INPUT_LEN || len(input) < MIN_INPUT_LEN {
		fmt.Printf("Error, %v must be between %v and %v characters\n", category, MIN_INPUT_LEN, MAX_INPUT_LEN)
		return false
	}
	if strings.ContainsAny(input, ILLEGAL_CHARS) {
		fmt.Printf("Error, %v has illegal characters\n", category)
		return false
	}
	return true
}

/*
Input Values: a server remote and a reader to read user input
Return Values: a tuple of strings (usr, token)
Preconditions: the user is trying to signup for an account
Postconditions: the user makes a new account if they enter
valid credentials
Behavior: the user is prompted to signup up for an account with
a username and a password. assuming that both are legal, the user
makes a new account with those credentials
Security Assumptions: none
*/
func PerformSignup(server *rpc.ServerRemote, reader *bufio.Reader)  (string, string) {
	// generate a signup handler on the server side
	fmt.Println("Please fill out the following prompts to create an account!")
	usr := GetUsername(reader)
	pass := GetPassword(reader)
	var token string 
	err := server.Call("signup", &token, usr, pass)
	if err != nil {
		fmt.Println("Error on signup")
		fmt.Println(err)
	}
	if strings.Compare(token, "") == 0 {
		fmt.Println("Invalid signup. That username is already taken!")
		return PerformSignup(server, reader)
	}
	return usr, token
}

/*
Input Values: a server remote and a reader for user input
Return Values: a tuple of strings (usr, token)
Preconditions: the user wants to login
Postconditions: the user logins if they have valid credentials
Behavior: the user is pronted for a username and password. this
informations is then validated by the sever which gives the user
a session token
Security Assumptions: the user is capable of entering valid credentials
*/
func EnforceLogin(server *rpc.ServerRemote, reader *bufio.Reader) (string, string) {
	usr := GetUsername(reader)
	pass := GetPassword(reader)
	
	//check login
	var ret string
	err := server.Call("validate", &ret, usr, pass)
	if err != nil {
		fmt.Println("Error on validation")
		fmt.Println(err)
		return EnforceLogin(server, reader)
	}
	fmt.Println(ret)
	if ret == RATE_MSG {
		seconds := SLEEP_TIME
		time.Sleep(time.Duration(seconds)*time.Second)
		return EnforceLogin(server, reader)
	}

	var token string
	server.Call("signin", &token, usr)
	return usr, token	
}

/*
Input Values: a client
Return Values: none
Preconditions: the client is the client whose
session has expired
Postconditions: the user needs to login again
Behavior: the client is informed their session has timed
out and they are prompted to login again
Security Assumptions: none
*/
func ReinforceLogin(c *Client) {
	fmt.Println("Your session has expired, please log in again.")
	usr, token := EnforceLogin(c.server, reader)
	c.token = token
	c.usr = usr
}

/*
Input Values: a reader to read user input
Return Values: a string which is the user input
Preconditions: the user has been prompted to enter
a username
Postconditions: the user returns a valid input
for a username
Behavior: the user is prompted for a username,
the user enters a username and the input is cleaned
and validated
Security Assumptions: the user is not bypassing the valid
input for a username
*/
func GetUsername(reader *bufio.Reader) string {
	fmt.Print("Enter username: ")
	usr, err := GetCleanedInput(reader)
	if err != nil {
		fmt.Println("Error on username entry")
		return GetUsername(reader)
	}
	if !IsValidInput(usr, "username") {
		return GetUsername(reader)
	}
	return usr
}

/*
Input Values: a reader for user input
Return Values: a string which is the desired password
Preconditions: the user has been prompted to enter
a password
Postconditions: the user returns a valid input for
a password
Behavior: the user is prompted for a password,
the user enters a password and the input is cleaned
and validated
Security Assumptions: the user is not bypassing the valid
input for a password
*/
func GetPassword(reader *bufio.Reader) string {
	fmt.Print("Enter password: ")
	pass, err := GetCleanedInput(reader)
	if err != nil {
		fmt.Println("Error on password entry")
		return GetPassword(reader)
	}
	if !IsValidInput(pass, "password") {
		return GetPassword(reader)
	}
	return pass
}

/*
Input Values: a message string
Return Values: none
Preconditions: none
Postconditions: the program is exited
Behavior: the function exits the program
Security Assumptions: the program was supposed to
be prompted to exit by the server
*/
func Exit(msg string) {
	fmt.Println(msg)
	fmt.Println("Exiting...")
	os.Exit(0)
}

/*
Input Values: a path for the file to upload to and 
the array of bytes which is the contents of the file
to upload
Return Values: an error and nil otherwise
Preconditions: none
Postconditions: the client uploads a file to the servers
filesystem unless there was an error
Behavior: the function makes a call to the server in order
to upload the file to the destination path on the users
filesystem 
Security Assumptions: none
*/
func (c *Client) Upload(path string, body []byte) (err error) {
	var ret string
	if len(body) > MAX_FILE_SIZE_BYTES {
		fmt.Println("Error cannot upload files greater than 500mb")
		return nil
	}
	err = c.server.Call("upload", &ret, c.usr, c.token, path, body)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

/*
Input Values: the path of the file to download
Return Values: the contents of the file to download
and an error/nil value
Preconditions: none
Postconditions: a file is downloaded from the servers
filesystem
Behavior: the function makes a call to the server in order 
to download a file from the specified path on the users filesystem
Security Assumptions: none
*/
func (c *Client) Download(path string) (body []byte, err error) {
	var ret internal.DownloadReturn
	err = c.server.Call("download", &ret, c.usr, c.token, path)
	if err != nil {
		return nil, client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return nil, fmt.Errorf(ret.Err)
	}
	return ret.Body, nil
}

/*
Input Values: a path of the directory to list
Return Values: a list of entries and a error/nil
Preconditions: none
Postconditions: the path specified is listed
Behavior: the function makes a call to the server to list
the information at the path in the users filesystem
Security Assumptions: none
*/
func (c *Client) List(path string) (entries []client.DirEnt, err error) {
	var ret internal.ListReturn
	err = c.server.Call("list", &ret, c.usr, c.token, path)
	if err != nil {
		return nil, client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return nil, fmt.Errorf(ret.Err)
	}
	var ents []client.DirEnt
	for _, e := range ret.Entries {
		ents = append(ents, e)
	}
	return ents, nil
}

/*
Input Values: a path to make a directory at
Return Values: a error/nil
Preconditions: none
Postconditions: a directory is made if the path is valid
Behavior: the function makes a call to the server to 
make a directory at the path on the users filesystem
Security Assumptions: none
*/
func (c *Client) Mkdir(path string) (err error) {
	var ret string
	err = c.server.Call("mkdir", &ret, c.usr, c.token, path)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

/*
Input Values: a path to a file/directory to remove
Return Values: a error/nil
Preconditions: none
Postconditions: a file/directory is removed
Behavior: the function makes a call to remove a
file/directory at the specified path on the users filesystem
Security Assumptions: none
*/
func (c *Client) Remove(path string) (err error) {
	var ret string
	err = c.server.Call("remove", &ret, c.usr, c.token, path)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}

/*
Input Values: none
Return Values: a path of the users working directory
and a error/nil
Preconditions: none
Postconditions: the user is returned a working directory
Behavior: the function makes a call to the server to display
the current working directory of the user on their filesystem
Security Assumptions: none
*/
func (c *Client) PWD() (path string, err error) {
	var ret internal.PWDReturn
	err = c.server.Call("pwd", &ret, c.usr, c.token)
	if err != nil {
		return "", client.MakeFatalError(err)
	}
	if ret.Err != "" {
		return "", fmt.Errorf(ret.Err)
	}
	if ret.Path == "" {
		ReinforceLogin(c)
		return c.usr, nil //special case to avoid blank prompt
	}
	return ret.Path, nil
}

/*
Input Values: a path to enter
Return Values: a error/nil
Preconditions: none
Postconditions: the user enters that directory
in the event that it is valid
Behavior: the function makes a call the server in
order to access the path on the users filesystem
Security Assumptions: none
*/
func (c *Client) CD(path string) (err error) {
	var ret string
	err = c.server.Call("cd", &ret, c.usr, c.token, path)
	if err != nil {
		return client.MakeFatalError(err)
	}
	if ret != "" {
		return fmt.Errorf(ret)
	}
	return nil
}