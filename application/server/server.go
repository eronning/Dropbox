package main

/*
Input Values:
Return Values:
Preconditions:
Postconditions:
Behavior:
Security Assumptions:
*/

import (
	// utility imports
	"fmt"
	"io/ioutil"
	"os"
	"time"
	"strings"
	"sync"
	"path/filepath"

	// encrypting/hashing information
	"hash"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha1"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"

	//relevant to SQL statements
	"database/sql"
	_ "github.com/mattn/go-sqlite3"

	//support code
	"../internal"
	"../lib/support/rpc"
)

var db *sql.DB
var err error
var usr_curr_dir_map map[string]string
var hasher256 hash.Hash = sha256.New()
var hasher1 hash.Hash = sha1.New()
var rwlock sync.RWMutex = sync.RWMutex{}
var FILE_WHITELIST = []string{"txt", "pdf", "jpg", "png", "jpeg", "gif", "mp3", "mp4"}

const (
	KEY_LENGTH int = 32
	LOGIN_RATE int64 = 10                           // can only submit login request every 10 seconds
	TOKEN_EXPIRATION int64 = 900					// 15 min token expiration
	FILESYSTEM_DIR string = "/root/filesystem/"
	FILESYSTEM_BASE string = "filesystem"
	DATABASE_DIR string = "/root/application/database/db.sqlite3"
	FLAG_ENCRYPT int = 1
	FLAG_DECRYPT int = 2
	USR_FILE_PERMISSIONS os.FileMode = 0600
	USR_DIR_PERMISSIONS os.FileMode = 0700
	MAX_FILE_SIZE_BYTES int = 500000000 				//500mb max file size
	//indices
	USR_INFO_USERNAME int = 0
	USR_INFO_PASSWORD int = 1
	USR_INFO_SALT int = 2
	USR_INFO_KEY int = 3
	//queries
	QUERY_GET_USER string = "SELECT * FROM users WHERE username = ?;"
	QUERY_INSERT_USER string = "INSERT INTO users VALUES (?,?,?,?);"
	QUERY_GET_LAST_LOGIN string = "SELECT last_attempt FROM login_attempts WHERE username = ?;"
	QUERY_INSERT_LAST_LOGIN string = "INSERT OR REPLACE INTO login_attempts VALUES (?,?);"
	QUERY_GET_EXISITING_KEY string = "SELECT * FROM users WHERE aes_key = ?;"
	QUERY_GET_TOKEN string = "SELECT * FROM tokens WHERE username = ?;"
	//return vals for IsValidLogin
	LOGIN_TIME string = "time"
	LOGIN_INVALID string = "invalid"
	RATE_MSG string = "Have to wait 10 seconds after invalid login to try again"
	INVALID_MSG string = "Invalid login"
	VALID_MSG string = "Login accepted"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %v <listen-address>\n", os.Args[0])
		os.Exit(1)
	}
	//connect to database
	DB_DRIVER := "sqlite3"
	db, err = sql.Open(DB_DRIVER, DATABASE_DIR)
	if err != nil {
		fmt.Println("Error on setting up db connection (my_server.go: main")
		fmt.Println(err)
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("Couldn't ping database")
		fmt.Println(err)
	}

	listenAddr := os.Args[1]

	// generate user current directory map
	usr_curr_dir_map = make(map[string]string)

	// register handlers
	rpc.RegisterHandler("upload", uploadHandler)
	rpc.RegisterHandler("download", downloadHandler)
	rpc.RegisterHandler("list", listHandler)
	rpc.RegisterHandler("mkdir", mkdirHandler)
	rpc.RegisterHandler("remove", removeHandler)
	rpc.RegisterHandler("pwd", pwdHandler)
	rpc.RegisterHandler("cd", cdHandler)

	//new handlers
	rpc.RegisterHandler("validate", isValidLogin)
	rpc.RegisterHandler("signin", signinHandler)
	rpc.RegisterHandler("signup", signupHandler)

	rpc.RegisterFinalizer(finalizer)
	fmt.Println("Starting Server!")
	err = rpc.RunServer(listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not run server: %v\n", err)
		os.Exit(1)
	}
}



/*
Input Values: An sql query, any arguments to the query
Return Values: The rows returned from the query
Preconditions: None
Postconditions: None
Behavior: Creates and executes a prepared statement
on the database, returns the result of the query
Security Assumptions: A prepared statement is not susceptible to SQL Injection
*/
func QueryDB(query string, args ...interface{}) *sql.Rows {
	rwlock.RLock()
	defer rwlock.RUnlock()
	var rows *sql.Rows
	stmt, err := db.Prepare(query)
	if err != nil {
		fmt.Println("Error creating prepared statement (my_server.go: QueryDB)")
		fmt.Println(err)
		return rows
	}
	rows, err = stmt.Query(args...)
	if err != nil {
		fmt.Println("Error executing prepared statement (my_server.go: QueryDB)")
		fmt.Println(err)
	}
	return rows
}


/*
Input Values: An sql query, any arguments to the query
Return Values: The number of rows found by the query
Preconditions: None
Postconditions: None
Behavior: Creates and executes a prepared statement
on the database, returns the result of the query
Security Assumptions: A prepared statement is not susceptible to SQL Injection
*/
func ExecDB(query string, args ...interface{}) sql.Result {
	rwlock.Lock()
	defer rwlock.Unlock()
	var res sql.Result
	stmt, err := db.Prepare(query)
	if err != nil {
		fmt.Println("Error creating prepared statement (my_server.go: ExecDB)")
		fmt.Println(err)
		return res
	}

	res, err = stmt.Exec(args...)
	if err != nil {
		fmt.Println("Error executing prepared statement (my_server.go: ExecDB)")
		fmt.Println(err)
	}
	return res
}

/*
Input Values: A valid username
Return Values: An array containing the user's
Username, Password, Salt, RC4 Key from the database
Preconditions: None
Postconditions: None
Behavior: Hashes the username and process the result
of querying the database from the sqlRows object into
a string array
Security Assumptions: Username is valid
*/
func GetUser(usr string) []string {
	hashed_usr := Hash1(usr)
	rows := QueryDB(QUERY_GET_USER, hashed_usr)
	var ret []string
	defer rows.Close()
	for rows.Next() {
		var (
			username string
			password string
			salt string
			key string
		)
		err = rows.Scan(&username, &password, &salt, &key)
		if err != nil {
			fmt.Println("Error accessing rows (my_server.go: GetUser)")
			fmt.Println(err)
		}
		ret = []string{username, password, salt, key}
	}
	return ret
}

/*
Input Values: Username of valid user
Return Values: Boolean stating whether the user is allowed to log in
Preconditions: None, this is the first step in the login process
Postconditions: The database holds a timestamp for this user
of the time they issued this login request
Behavior: Queries the database for the last time the person
logged in, if it is more than the limit or the first attempt,
they are allowed to log in
Security Assumptions: Caller of this function has received
clean input from the client
*/
func canLogin(usr string) string {
	//find the last time they logged in
	query := QUERY_GET_LAST_LOGIN
	rows := QueryDB(query, Hash1(usr))
	ret := LOGIN_INVALID
	defer rows.Close()
	for rows.Next() {
		var (
			last int64
		)
		err = rows.Scan(&last)
		if err != nil {
			fmt.Println("Error accessing rows (my_server.go: canLogin")
			fmt.Println(err)
			return LOGIN_INVALID
		}
		diff := time.Now().Unix() - last
		if diff <= LOGIN_RATE {
			ret = LOGIN_TIME
		}
	}
	return ret
}

/*
Input Values: username
Return Values: None
Preconditions: There is an active database connection
Postconditions: The database holds a timestamp for this user
of the time they issued this login request
Behavior: Saves the current time and requesting user
in the database
Security Assumptions: None
*/
func addLoginAttempt(usr string) {
	curr_time := time.Now().Unix()
	hashed_usr := Hash1(usr)
	query := QUERY_INSERT_LAST_LOGIN
	ExecDB(query, hashed_usr, curr_time)
}

/*
Input Values: username and password
Return Values: a string containing a message
signifying the validity of the function. this
string is used in the client to determine how to proceed
Preconditions: username has been cleaned and length checked
Postconditions: The users login attempt is saved in the
database
Behavior: Checks the password against the one saved
in the database associated with the input username.
If they match, permits login
Security Assumptions: Username has already been
cleaned to prevent SQL injection (and prepared statement
should already handle it)
*/
func isValidLogin(usr string, pass string) string {
	canLogin := canLogin(usr)
	if canLogin == LOGIN_TIME {
		return RATE_MSG
	}
	addLoginAttempt(usr) //record this as a login attempt
	usr_info := GetUser(usr)
	// check if a user was found
	if len(usr_info) != 0 {
		// gather user info
		salt := usr_info[USR_INFO_SALT]
		password := usr_info[USR_INFO_PASSWORD]
		hashed_password := Hash256(pass, salt)
		// compare passwords
		if strings.Compare(hashed_password, password) == 0 {
			return VALID_MSG
		}
	}
	return RATE_MSG;
}

/*
Input Values: username, token for user
Return Values: true if token is valid for user
Preconditions: user is logged in and has
been issued a token that is saved in the database
Postconditions: everything in the database should
remain how it was
Behavior: checks the database for the token associated with
the username and compares it to the input token
Security Assumptions: Username has already been
cleaned to prevent SQL injection (and prepared statement
should already handle it)
*/
func IsValidToken(usr string, token string) bool {
	//check username/token pair for validity
	query := QUERY_GET_TOKEN
	hashed_usr := Hash1(usr)
	rows := QueryDB(query, hashed_usr)
	defer rows.Close()
	for rows.Next() {
		var (
			username string
			tok string
			token_time int64
		)
		err = rows.Scan(&username, &tok, &token_time)
		if err != nil {
			fmt.Println("Error accessing rows (my_server.go: IsValidToken)")
			fmt.Println(err)
			return false
		}
		//check token
		same_token := strings.Compare(token, tok) == 0
		//check time
		curr_time := time.Now().Unix()
		// curr_time := 0
		time_diff := curr_time - token_time
		valid_time := time_diff <= TOKEN_EXPIRATION
		return same_token && valid_time  
	}
	return false
}

/*
Input Values: filepath and file body
Return Values: boolean and an explanation
Preconditions: None
Postconditions: None
Behavior: Checks the size of the file against
the determined limit, returns false if the file
is too big
Security Assumptions: the file is not so big
that it will cause a seg fault
*/
func IsValidFile(path string, body []byte) (bool, string) {
	if len(body) > MAX_FILE_SIZE_BYTES {
		return false, "File size must be under 500mb"
	}
	return true, "File accepted"
}

/*
Input Values: a hashed form of the username
Return Values: a new token for that user
Preconditions: the user is logged in and
their token has expired
Postconditions: the user has a new token
associated with them in the database
Behavior: generates a random string
and calls a function to have it saved
in the database
Security Assumptions: username exists in the database
*/
func generateNewToken(hashed_usr string) string {
	//generate random string
	token := GenerateRandomString()
	SaveToken(hashed_usr, token)
	return token
}

/*
Input Values: a hashed username and a token to be
associated with that user
Return Values: None
Preconditions: user is logged in, token is unique,
user's token has expired
Postconditions: user/token pair now saved in the database
Behavior: saves the user, token, and current time in the
database for future reference
Security Assumptions: token is not a duplicate
and 
*/
func SaveToken(hashed_usr string, token string) {
	curr_time := time.Now().Unix()
	query := "INSERT OR REPLACE INTO tokens VALUES (?,?,?);"
	ExecDB(query, hashed_usr, token, curr_time)
}

/*
Input Values: a username
Return Values: token for that user
Preconditions: None
Postconditions: User is now registered
in the system with an active token
Behavior: calls a function that manages signing
the user in
Security Assumptions: username supplied has
been cleaned of malicious characters
*/
func signinHandler(usr string) string {
	token := UserSignIn(usr)
	return token
}

/*
Input Values: a username and password
Return Values: a new token for the user
Preconditions: None
Postconditions: User is now registered
in the system with an active token
Behavior: checks to see if the username
does not exist, then generates a unique
key for the user and a salt, saves
the hashed username, hashed/salted password,
salt, and key in the database
Security Assumptions: hash and salt are
unique and cryptographically secure
*/
func signupHandler(usr string, pass string) string {
	// query for the number of users with the passed in username
	query := "SELECT count(*) FROM users WHERE username = ?;"
	hashed_usr := Hash1(usr)
	rows := QueryDB(query, hashed_usr)
	rows.Next()
	var count int
	// scan the result
	err = rows.Scan(&count)
	if err != nil {
		fmt.Println("ERROR: querying for number of users with a given username (my_server.go: signupHandler)")
		fmt.Println(err)
		return "";
	}
	rows.Close()
	// make sure that username is unique
	if count == 0 {
		// generate a per user salt
		salt := GenerateRandomString()
		// hash the password with the generated salt
		hashed_pass := Hash256(pass, salt)
		// make the RC4 key for the user
		key := GenerateRandomString()
		for KeyExists(key) {
			key = GenerateRandomString()
		}
		// insert the information into the DB
		query := "INSERT INTO users VALUES (?,?,?,?);"
		// make a call to execute the query
		ExecDB(query, hashed_usr, hashed_pass, salt, key)
		// mkdir for new user
		encrypted := EncryptString(hashed_usr, key)
		path := GetBaseDir(encrypted)
		usr_info := []string{hashed_usr, hashed_pass, salt, key}
		token := NewUserSignIn(path, usr, usr_info)
		return token
	}
	return ""
}

/*
Input Values: a key
Return Values: true if the key
has already been used
Preconditions: valid database connection
Postconditions: none
Behavior: querys the database for the
input key
Security Assumptions: query cannot be sql injected
*/
func KeyExists(key string) bool {
	rows := QueryDB(QUERY_GET_EXISITING_KEY, key)
	defer rows.Close()
	for rows.Next() {
		return true
	}
	return false
}

/*
Input Values: file path, the users username and an 
array containing the hashed username, password, salt,
and key of the active user
Return Values: a new token for that user
Preconditions: none
Postconditions: user now has a root directory
Behavior: makes a root directory for the new user 
and puts them in it
Security Assumptions: path has been sanitized
*/
func NewUserSignIn(path string, usr string, usr_info []string) string {
	// make a user directory
	Mkdir(path, usr, usr_info)
	// update the user current directory
	Chdir(path, usr, usr_info)
	return generateNewToken(usr_info[USR_INFO_USERNAME])
}

/*
Input Values: a valid username
Return Values: a new token for that user
Preconditions: the user is signing in or
has an expired token
Postconditions: token for user is valid
Behavior: wrapper for accomplishing signin
for a current user
Security Assumptions: username has been
cleaned for the sql query
*/
func UserSignIn(usr string) string {
	// get the user information from the db
	usr_info := GetUser(usr)
	// get the users base directory
	path := GetUserBaseDir(usr_info)
	// update the current user directory
	Chdir(path, usr, usr_info)
	return generateNewToken(usr_info[USR_INFO_USERNAME])
}

/*
Input Values: a file path
Return Values: that file path
append with the base directory of the
server's file system
Preconditions: None
Postconditions: None
Behavior: Appends the base filesystem directory
constant to the given filepath
Security Assumptions: The path passed in is valid
path that has been cleaned, parsed, and made into
an absolute path
*/
func GetBaseDir(path string) string {
	return FILESYSTEM_DIR + path
}

/*
Input Values: an array containing the user's
username, password, salt, and rc4 key
Return Values: a string representing the
path to the user's base/root directory
Preconditions: the user has been authenticated
Postconditions: none
Behavior: Returns the base or root directory
for the given user
Security Assumptions: given user info matches
the active user on the system
*/
func GetUserBaseDir(usr_info []string) string {
	usr_dir := EncryptString(usr_info[USR_INFO_USERNAME], usr_info[USR_INFO_KEY])
	return GetBaseDir(usr_dir)
}

/*
Input Values: A string to encrypt and a key
to encrypt with
Return Values: An RC4 encrypted form of the 
given string
Preconditions: None
Postconditions: None
Behavior: uses the RC4 encryption system to
encrypt the given string
Security Assumptions: the given key is long
enough to encrypt the string securely
*/
func EncryptString(to_encrypt string, key_string string) string {
	key := DecodeBase64(key_string)
	plaintext := []byte(to_encrypt)
	// create the cipher
	c, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Println("ERROR: there was a key size error (my_server.go: EncryptString)")
		fmt.Println(err) 
	}
	// make a empty byte array to fill
	ciphertext := make([]byte, len(plaintext))
	// create the ciphertext
	c.XORKeyStream(ciphertext, plaintext)
	return EncodeBase64(ciphertext)
}

/*
Input Values: A string to decrypt and a key
to decrypt with
Return Values: A decrypted form of the 
given string
Preconditions: None
Postconditions: None
Behavior: uses the RC4 encryption system to
decrypt the given string with the given key
Security Assumptions: the given key is long
enough to decrypt the string and is the same
one that was used to encrypt the string in
this symmetric key system. if the key is not
the same, the returned string is garbage
*/
func DecryptString(to_decrypt string, key_string string) string {
	ciphertext := DecodeBase64(to_decrypt)
	key := DecodeBase64(key_string)
	// create the cipher
	c, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Println("ERROR: there was a key size error (my_server.go: DecryptString)")
		fmt.Println(err) 
	}
	// make an empty byte array to fill
	plaintext := make([]byte, len(ciphertext))
	// decrypt the ciphertext
	c.XORKeyStream(plaintext, ciphertext)
    return string(plaintext)
}

/*
Input Values: n, the number of random
bytes to be produced
Return Values: a byte array containing n
random bytes
Preconditions: None
Postconditions: None
Behavior: Returns n random bytes
Security Assumptions: The bytes are
truly random
*/
func GenerateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    // Note that err == nil only if we read len(b) bytes.
    if err != nil {
        return nil, err
    }
    return b, nil
}

/*
Input Values: None
Return Values: A random string of 32
characters 
Preconditions: None
Postconditions: None
Behavior: uses the generate random bytes
method and then encodes the returned bytes
into base64
Security Assumptions: the bytes generated
by generateRandomBytes() are truly random
*/
func GenerateRandomString() (string) {
    b, err := GenerateRandomBytes(KEY_LENGTH)
    if err != nil {
		fmt.Println("ERROR: could not generate random bytes (my_server.go: GenerateRandomString)")
		fmt.Println(err)
		return ""
	}
    return EncodeBase64(b)
}

/*
Input Values: A string to be decoded
to base 64 url encoding
Return Values: A base 64 url decoded
string
Preconditions: None
Postconditions: None
Behavior: returns a byte array equating
to the given string
Security Assumptions: given string is
possible to be decoded
*/
func DecodeBase64(s string) []byte {                                                                                                                                                                        
    bytes, err := base64.URLEncoding.DecodeString(s)                                                                                                                                                         
    if err != nil { 
    	fmt.Println("ERROR: There was an error decoding string (my_server.go: DecodeBase64)")
    	fmt.Println(err)
    	return []byte{}
    }                                                                                                                                                                            
    return bytes   
}  

/*
Input Values: A byte array to be encoded to
base64 url string
Return Values: An string representing the 
given byte array
Preconditions: None
Postconditions: None
Behavior: use base64 library to encode the
given bytes
Security Assumptions: byte array can be
encode to base64 url
*/
func EncodeBase64(bytes []byte) string {
	return base64.URLEncoding.EncodeToString(bytes)
}

/*
Input Values: Two strings: A password and a salt
Return Values: A sha256 hash of the
given password and salt
Preconditions: None
Postconditions: None
Behavior: concatenates the given password
and salt and hashes the value with SHA256
Security Assumptions: None
*/
func Hash256(pass string, salt string) string {
	combined_bytes := []byte(pass + salt)
	hash_bytes := hasher256.Sum(combined_bytes)
	return hex.EncodeToString(hash_bytes)
}

/*
Input Values: A string to be hashed
Return Values: A SHA1 hash of the given
string
Preconditions: None
Postconditions: None
Behavior: hashes the given string with
SHA1
Security Assumptions: None
*/
func Hash1(usr string) string {
	bytes := []byte(usr)
	hash_bytes := hasher1.Sum(bytes)
	return hex.EncodeToString(hash_bytes)
}

/*
Input Values: A filepath
Return Values: An array containing the
elements of the input string, split by '/'
Preconditions: None
Postconditions: None
Behavior: calls the string library to split
the given string on '/'
Security Assumptions: None
*/
func SplitPath(path string) []string {
	return strings.Split(path, "/")
}

/*
Input Values: An array of strings
Return Values: The strings in the given array
concatenated with '/'
Preconditions: None
Postconditions: None
Behavior: call the string library to join
the strings in the array with '/'
Security Assumptions: None
*/
func JoinPath(path_arr []string) string {
	return strings.Join(path_arr, "/")
}

/*
Input Values: A string representing a filepath
Return Values: True if the given path is absolute
Preconditions: None
Postconditions: None
Behavior: Checks the given string for the 
'/' prefix, returns true if it exists
Security Assumptions: None
*/
func isAbsolutePath(path string) bool {
	return strings.HasPrefix(path, "/")
}

/*
Input Values: a filepath and the
username, password, salt, and key of a user
Return Values: the given path encrypted with
the user's rc4 key
Preconditions: the user authenticated and has
been given a unique rc4 key
Postconditions: None
Behavior: splits the input path on '/', encrypts
each element, rejoins them with '/'
Security Assumptions: The given rc4 key matches
the given user and the active user that triggered
the function call
*/
func EncryptPath(path string, usr_info []string) string {
	return JoinPath(CipherPathStrings(SplitPath(path), usr_info[USR_INFO_KEY], FLAG_ENCRYPT))
}

/*
Input Values: a filepath and the
username, password, salt, and key of a user
Return Values: the given path decrypted with
the user's rc4 key
Preconditions: the user authenticated and has
been given a unique rc4 key, the path given
has been previously encrypted with the given key
Postconditions: None
Behavior: splits the input path on '/', decrypts
each element, rejoins them with '/', if given
an absolute path we prepend the user's base directory
onto it to prevent getting out of their root
Security Assumptions: The given rc4 key matches
the given user and the active user that triggered
the function call
*/
func ParsePWD(usr_info []string, path string) []string {
	return SplitPath(strings.TrimPrefix(path, GetUserBaseDir(usr_info)))
}

/*
Input Values: a file/directory path and the
users base directory path
Return Values: a boolean on whether or not the
path is allowed for that user
Preconditions: the user directory path being checked
against is the user that is requesting the path
Postconditions: None
Behavior: checks to see if the prefix of the path
to access matches the users base directory (i.e they
are staying inside of their directory)
Security Assumptions: The given user directory matches
the given user and the active user that triggered
the function call
*/
func ValidPath(path string, usr_dir string) bool {
	return strings.HasPrefix(path, usr_dir)
}

/* MOST EPIC FUNCTION EVER!!! :)
Input Values: a file/directory path, and 
the users information
Return Values: the path to access and a boolean
on whether or not it can be accessed
Preconditions: the user authenticated and has
been given a unique rc4 key
Postconditions: The user is authenticated to access
this path
Behavior: the function checks the users current working
directory and then gets the absolute path of the path 
the user is attempting to access. The function verifies that 
the resultant path is valid for the user to access
Security Assumptions: The given rc4 key matches
the given user and the active user that triggered
the function call
*/
func AuthenticatePath(path string, usr_info []string) (bool, string) {
	// get the users current directory
	usr_path := usr_curr_dir_map[usr_info[USR_INFO_USERNAME]]
	// get the users base file directory path
	dir_path := GetUserBaseDir(usr_info)
	// parse the path and encrypt with user key
	encrypt_path := EncryptPath(path, usr_info)
	// get that absolute path
	abs_path, _ := filepath.Abs(usr_path + "/" + encrypt_path)
	// check if the path is absolute
	if isAbsolutePath(path) {
		abs_path, _ = filepath.Abs(dir_path + encrypt_path)
		return ValidPath(abs_path, dir_path), dir_path + encrypt_path
	}
	// make sure the path is in the users directory
	return ValidPath(abs_path, dir_path), abs_path
}

/*
Input Values: a path split by '/', the key to 
be used on the values and a flag to decrypt/encrypt
Return Values: the encrypted/decrypted values 
Preconditions: the rc4 key being used is meant to be
used on the values passed in
Postconditions: None
Behavior: The function takes in all the values and 
encrypts/decrypts each one of them unless they are a 
'.' or '..' which are valid paths in the encrypted filesystem
Security Assumptions: The given rc4 key matches
the given values that are passed in
*/
func CipherPathStrings(values []string, key string, flag int) []string {
	for i, val := range values {
		// decrypt all file/directory names
		if strings.Compare(val, "..") != 0 && strings.Compare(val, ".") != 0{
			switch flag {
				case FLAG_ENCRYPT:
					values[i] = EncryptString(val, key)
				case FLAG_DECRYPT:
					values[i] = DecryptString(val, key)
			}
		}
	}
	return values
}


/*
Input Values: a string of the users name
and a string array of the user information
Return Values: the users pwd
Preconditions: the user information is for 
the specific user that was passed in
Postconditions: None
Behavior: gets the current working directory
of the user, parses out the path to the users base
directory and decrypts the rest of the path. Then
it returns a path which is the username of the user
and the rest of the decrypted working directory
Security Assumptions: The user is already authenticated
and the users key matches that of the directory that they
are in. Otherwise the PWS will return garbage, which means
that an attacker will not be able to distinguish their
location or what files/directories are.
*/
func GeneratePWD(usr string, usr_info []string) string {
	// get the working directory
	path := usr_curr_dir_map[usr_info[USR_INFO_USERNAME]]
	// parse the path to get user section
	values := ParsePWD(usr_info, path)
	// get the decrypt directory names for the user to see
	values = CipherPathStrings(values, usr_info[USR_INFO_KEY], FLAG_DECRYPT)
	// check that there is a path and it is the users
	return usr + JoinPath(values)
}

/*
Input Values: An active user's username and
current token
Return Values: their working directory
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling pwd
returns nothing if the token is invalid,
returns the working directory of the user if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code
*/
func pwdHandler(usr string, token string) internal.PWDReturn {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		path := GeneratePWD(usr, usr_info)
		return internal.PWDReturn{Path: path}
	}
	return internal.PWDReturn{}
}

/*
Input Values: An active user's username and
current token, and a directory to move to
Return Values: the directory they moved
to
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling cd
returns nothing if the token is invalid,
returns the current directory of the user if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code
*/
func cdHandler(usr string, token string, path string) string {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		// authenticate the path
		valid, encrypt_path := AuthenticatePath(path, usr_info)
		if valid {
			return Chdir(encrypt_path, path, usr_info)
		}  
	}
	return ErrorMessage("chdir", path)
}

/*
Input Values: An active user's username and
current token, and a directory to list
Return Values: the contents of the given path
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling ls
returns nothing if the token is invalid,
returns the inquired directory if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code
*/
func listHandler(usr string, token string, path string) internal.ListReturn {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		// authenticate the path
		valid, encrypt_path := AuthenticatePath(path, usr_info)
		if valid {
			return ReadDir(encrypt_path, path, usr_info)
		}
	}
	return internal.ListReturn{Err: ErrorMessage("open", path)}
}

/*
Input Values: An active user's username and
current token, and a directory to create
Return Values: the result of making a new directory
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling mkdir
returns nothing if the token is invalid,
returns the result of making a directory if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code
*/
func mkdirHandler(usr string, token string, path string) string {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		// authenticate the path
		valid, encrypt_path := AuthenticatePath(path, usr_info)
		if valid {
			return Mkdir(encrypt_path, path, usr_info)
		}
	}
	return ErrorMessage("making directory", path)
}

/*
Input Values: An active user's username and
current token
Return Values: the result of removing a file
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling rm
returns nothing if the token is invalid,
returns the result of removing a file if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code
*/
func removeHandler(usr string, token string, path string) string {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		// authenticate the path
		valid, encrypt_path := AuthenticatePath(path, usr_info)
		if valid {
			return Remove(encrypt_path, path, usr_info)
		}
	}
	return ErrorMessage("remove", path)
}

/*
Input Values: An active user's username and
current token
Return Values: the result of uploading a file
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling upload
returns nothing if the token is invalid,
returns the result of uploading a file if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code, the uploaded
file and path are not executable and do not contain any malicious code
*/
func uploadHandler(usr string, token string, path string, body []byte) string {
	if IsValidToken(usr, token) {
		valid_file, reason := IsValidFile(path, body)
		if valid_file {
			usr_info := GetUser(usr)
			// authenticate the path
			valid, encrypt_path := AuthenticatePath(path, usr_info)
			if valid {
				return WriteFile(encrypt_path, body)
			}
		} else {
			return reason
		}
	}
	return ErrorMessage("upload", path)
}

/*
Input Values: An active user's username and
current token
Return Values: the result of downloading a file
Preconditions: the user has logged in with
a valid username/password pair and has been
given a valid token
Postconditions: None
Behavior: Handler for client calling download
returns nothing if the token is invalid,
returns the result of uploading a file if the token is valid
Security Assumptions: the given username/string pair exist in the
database and do not contain any malicious sql code, the uploaded
file and path are not executable and do not contain any malicious code
*/
func downloadHandler(usr string, token string, path string) internal.DownloadReturn {
	if IsValidToken(usr, token) {
		usr_info := GetUser(usr)
		// authenticate the path
		valid, encrypt_path := AuthenticatePath(path, usr_info)
		if valid {
			return ReadFile(encrypt_path, path, usr_info)
		}
	}
	return internal.DownloadReturn{Err: ErrorMessage("download", path)}
}


/*
Input Values: a filepath, the unencrypted filepath and 
information for the user requesting the file
Return Values: the contents of the file
Preconditions: the user has been authenticated and
the file exists in the filesystem
Postconditions: None
Behavior: reads the requested file
Security Assumptions: the file being read and the given
path do not execute any malicious code
and the user info applies to the user making the request
*/
func ReadFile(path string, plaintext_path string, usr_info []string) internal.DownloadReturn {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return internal.DownloadReturn{Err: ErrorMessage("open", plaintext_path)}
	}
	return internal.DownloadReturn{Body: body}
}

/*
Input Values: a filepath, the unencrypted filepath and 
information for the user requesting the file
Return Values: an empty string
Preconditions: the user has been authenticated and
has supplied a valid path
Postconditions: None
Behavior: reads the requested file onto the system
Security Assumptions: the file being read and the given
path do not execute any malicious code
and the user info applies to the user making the request
*/
func WriteFile(path string, body []byte) string {
	err := ioutil.WriteFile(path, body, USR_FILE_PERMISSIONS)
	if err != nil {
		return err.Error()
	}
	return ""
}

/*
Input Values: a path to a directory, the unencrypted directory path
and information for the user requesting the directory
Return Values: the contents of the directory
Preconditions: the user has been authenticated and
the directory is permitted to them
Postconditions: None
Behavior: reads the requested directory
Security Assumptions: the user has supplied a valid filepath
and the user info applies to the user making the request
*/
func ReadDir(path string, plaintext_path string, usr_info []string) internal.ListReturn {
	fis, err := ioutil.ReadDir(path)
	if err != nil {
		return internal.ListReturn{Err: ErrorMessage("open", plaintext_path)}
	}
	var entries []internal.DirEnt
	for _, fi := range fis {
		// make sure to decrypt each file/directory name so it is readable
		entries = append(entries, internal.DirEnt{
			IsDir_: fi.IsDir(),
			Name_:  DecryptString(fi.Name(), usr_info[USR_INFO_KEY]),
		})
	}
	return internal.ListReturn{Entries: entries}
}

/*
Input Values: a path to a new directory, the unencrypted path
and information for the user requesting the directory
Return Values: string representing an error, if one occurred
Preconditions: the user has been authenticated and
already has a root directory in the system
Postconditions: None
Behavior: creates a directory at the intended location
Security Assumptions: the user has supplied a valid filepath
and the user info applies to the user making the request
*/
func Mkdir(path string, plaintext_path string, usr_info []string) string {
	err := os.Mkdir(path, USR_DIR_PERMISSIONS)
	if err != nil {
		return ErrorMessage("making directory", plaintext_path)
	}
	return ""
}

/*
Input Values: a path to an existing directory, the unencrypted path
and information for the user requesting the directory
Return Values: string representing an error, if one occurred
Preconditions: the user has been authenticated and
already has a root directory in the system
Postconditions: None
Behavior: moves the user to the requested directory
Security Assumptions: the user has supplied a valid filepath 
and the user info applies to the user making the request
*/
func Chdir(path string, plaintext_path string, usr_info []string) string {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return ErrorMessage("chdir", plaintext_path)
	}
	// path was valid: save the current working directory for the user
	usr_curr_dir_map[usr_info[USR_INFO_USERNAME]] = path
	return ""
}

/*
Input Values: a path to file or directory to be removed, the unencrypted
filepath and the information of the user requesting the remove
Return Values: string representing an error, if one occurred
Preconditions: the user has been authenticated and
already has a root directory in the system
Postconditions: None
Behavior: removes the file/directory in the supplied path
Security Assumptions: the user has supplied a valid filepath
and the user info applies to the user making the request
*/
func Remove(path string, plaintext_path string, usr_info []string) string {
	err := os.Remove(path)
	if err != nil {
		return ErrorMessage("remove", plaintext_path)
	}
	return ""
}

/*
Input Values: An error type and a relevant path
Return Values: the supplied strings arranged in
a message informative to the user
Preconditions: None
Postconditions: None
Behavior: concatenates the given strings into
a prepared message
Security Assumptions: None
*/
func ErrorMessage(error_type string, path string) string {
	return error_type + " " + path + ": no such file or directory"
}

/*
Input Values: None
Return Values: None
Preconditions: None
Postconditions: None
Behavior: Prints a departure message when the
server program ends
Security Assumptions: None
*/
func finalizer() {
	fmt.Println()
	fmt.Println("See ya!")
}
