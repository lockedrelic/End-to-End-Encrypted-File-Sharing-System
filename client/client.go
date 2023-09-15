package client

import (
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
	"strconv"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

const blocksize = 10

type User struct {
	Username string

	SharePublicKeyEnc   userlib.PKEEncKey
	SharePrivateKeyEnc  userlib.PKEDecKey
	SharePublicKeySign  userlib.DSVerifyKey
	SharePrivateKeySign userlib.DSSignKey

	FilestructEnc []byte
	FilestructMac []byte
	SharetreeEnc  []byte
	SharetreeMac  []byte
}

type filestruct struct {
	RootEnc []byte
	RootMac []byte
	First   userlib.UUID
}

type filenode struct {
	Lastcounter int
	Last        userlib.UUID
	Next        userlib.UUID
	Data        []byte
}

type sharestruct struct {
	F userlib.UUID
	E []byte
	M []byte
}

type sharetree struct {
	Sharemap map[string]uuid.UUID
	Filemap  map[uuid.UUID][][]byte
}

// add byte arrays together
func concatenateByteArrays(a []byte, b []byte) []byte {
	result := make([]byte, len(a)+len(b))
	copy(result[:len(a)], a)
	copy(result[len(a):], b)
	return result
}

func userpasskeyGen(username string, password string) []byte {
	p1 := userlib.Hash([]byte(username))
	p2 := userlib.Hash([]byte(password))
	p3 := concatenateByteArrays(p1, p2)
	return userlib.Hash(p3)[:16]
}

func filestructKeyGen(username string, filename string) userlib.UUID {
	step1 := userpasskeyGen(username, filename)
	fKey, _ := uuid.FromBytes(step1)
	return fKey
}

func generateSharetreeKey(username string, filename string) userlib.UUID {
	p1 := userlib.Hash([]byte(username))
	p2 := userlib.Hash([]byte(filename))
	p3 := userlib.Hash([]byte("sharetree"))
	bytes := concatenateByteArrays(p1, p2)
	bytes = concatenateByteArrays(bytes, p3)
	hashed := userlib.Hash(bytes)[:16]
	sKey, _ := uuid.FromBytes(hashed)
	return sKey
}

func EncMacGen(content []byte, symkey []byte, mackey []byte) []byte {
	IV := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(symkey, IV, content)
	hmac, _ := userlib.HMACEval(mackey, ciphertext)
	return concatenateByteArrays(ciphertext, hmac)
}

func VerifyDec(ciphertext []byte, symkey []byte, mackey []byte) (__ []byte, err error) {
	hmac := ciphertext[len(ciphertext)-64:]
	encrypted := ciphertext[:len(ciphertext)-64]
	newHmac, err := userlib.HMACEval(mackey, encrypted)
	valid := userlib.HMACEqual(newHmac, hmac)
	if !valid {
		return nil, errors.New(strings.ToTitle("invalid"))
	}
	originalText := userlib.SymDec(symkey, encrypted)
	return originalText, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New(strings.ToTitle("username cannot be empty"))
	}
	userkey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	_, ok := userlib.DatastoreGet(userkey)
	if ok {
		return nil, errors.New(strings.ToTitle("username already exists"))
	}
	_, ok = userlib.KeystoreGet(username + "shareenc")
	if ok {
		return nil, errors.New(strings.ToTitle("username already exists"))
	}
	_, ok = userlib.KeystoreGet(username + "sharesign")
	if ok {
		return nil, errors.New(strings.ToTitle("username already exists"))
	}
	pk1, sk1, _ := userlib.PKEKeyGen()
	sk2, pk2, _ := userlib.DSKeyGen()

	userdata := User{
		Username: username,

		SharePublicKeyEnc:   pk1,
		SharePrivateKeyEnc:  sk1,
		SharePublicKeySign:  pk2,
		SharePrivateKeySign: sk2,

		FilestructEnc: userlib.RandomBytes(16),
		FilestructMac: userlib.RandomBytes(16),
		SharetreeEnc:  userlib.RandomBytes(16),
		SharetreeMac:  userlib.RandomBytes(16),
	}

	// may need to make sure key reuse is not implicit in the following:
	// could mac it with just the password, and encrypt/decrypt with the user-passkey combo to change it up a little

	enckey := userpasskeyGen(username, password)
	userbytes, err := json.Marshal(userdata)
	usercipher := EncMacGen(userbytes, enckey, enckey)

	// currently have 4 sets of public-private key pairs, so we need to set all the below:
	err = userlib.KeystoreSet(username+"shareenc", pk1)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"sharesign", pk2)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userkey, usercipher)

	return &userdata, nil
}
func GetUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	userdataptr = &userdata

	if username == "" {
		return nil, errors.New(strings.ToTitle("username cannot be empty"))
	}

	userkey, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	ciphertext, ok := userlib.DatastoreGet(userkey)
	if !ok {
		return nil, errors.New(strings.ToTitle("there is no initialized user for the given username"))
	}

	symKey := userpasskeyGen(username, password)

	// small changes need to be made so we can tell the difference between invalid login credentials and tampering?

	user, err := VerifyDec(ciphertext, symKey, symKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("invalid"))
	}
	var udata User
	err = json.Unmarshal(user, &udata)
	return &udata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	storageKey := filestructKeyGen(userdata.Username, filename)
	_, exists := userlib.DatastoreGet(storageKey)
	var rootMac []byte
	var rootEnc []byte
	var curfilestruct filestruct
	if exists {
		curfilepointer, _ := userdata.loadFileStruct(filename)
		if curfilepointer == nil {
			exists = false
		}
	}
	if exists {
		curfilepointer, _ := userdata.loadFileStruct(filename)
		if curfilepointer == nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		curfilestruct = *curfilepointer
		rootEnc = curfilestruct.RootEnc
		rootMac = curfilestruct.RootMac
	} else {
		rootEnc = userlib.RandomBytes(16)
		rootMac = userlib.RandomBytes(16)
	}

	// do the firstnode first:
	end := blocksize
	if end > len(content) {
		end = len(content)
	}
	slice := content[0:end]
	firstNode := filenode{
		Data: slice,
	}
	firstUUID := uuid.New()
	if exists {
		firstUUID = curfilestruct.First
	}
	var prevUUID uuid.UUID
	var prevNode filenode
	counter := 0
	for i := blocksize; i < len(content); i += blocksize {
		end := i + blocksize
		if end > len(content) {
			end = len(content)
		}
		slice := content[i:end]
		macKey, err := userlib.HashKDF(rootMac, []byte("mac-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		symKey, err := userlib.HashKDF(rootEnc, []byte("enc-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		newnode := filenode{
			Data: slice,
		}
		if counter > 0 {
			curaddress := uuid.New()
			prevNode.Next = curaddress
			byteform, _ := json.Marshal(prevNode)
			block := EncMacGen(byteform, symKey[:16], macKey[:16])
			userlib.DatastoreSet(prevUUID, block)
			prevUUID = curaddress
		} else {
			prevUUID = uuid.New()
			firstNode.Next = prevUUID
		}
		prevNode = newnode
		counter += 1
	}

	// encrypt then mac the last block
	if counter != 0 {
		lastMac, err := userlib.HashKDF(rootMac, []byte("mac-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		lastSym, err := userlib.HashKDF(rootEnc, []byte("enc-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		prevNode.Next = uuid.Nil
		byteform, _ := json.Marshal(prevNode)
		block := EncMacGen(byteform, lastSym[:16], lastMac[:16])
		userlib.DatastoreSet(prevUUID, block)
	}

	// encrypt then mac the first block
	firstMac, err := userlib.HashKDF(rootMac, []byte("mac-key"+strconv.Itoa(0)))
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	firstSym, err := userlib.HashKDF(rootEnc, []byte("enc-key"+strconv.Itoa(0)))
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	firstNode.Lastcounter = counter
	if counter == 0 {
		firstNode.Last = firstUUID
	} else {
		firstNode.Last = prevUUID
	}
	byteform, _ := json.Marshal(firstNode)
	block := EncMacGen(byteform, firstSym[:16], firstMac[:16])
	userlib.DatastoreSet(firstUUID, block)

	// put the filestruct in the Datastore

	var toStore []byte
	if exists {
		return
	}
	curstruct := filestruct{
		RootEnc: rootEnc,
		RootMac: rootMac,
		First:   firstUUID,
	}
	filestructBytes, err := json.Marshal(curstruct)
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	toStore = EncMacGen(filestructBytes, userdata.FilestructEnc, userdata.FilestructMac)
	userlib.DatastoreSet(storageKey, toStore)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	pointer, _ := userdata.loadFileStruct(filename)
	if pointer == nil {
		return errors.New(strings.ToTitle("File access not granted"))
	}
	curFileStruct := *pointer
	pointer2 := loadFileNode(curFileStruct.First, curFileStruct.RootMac, curFileStruct.RootEnc, 0)
	if pointer2 == nil {
		return errors.New(strings.ToTitle("File access not granted"))
	}
	firstNode := *pointer2
	var lastNode filenode
	if firstNode.Next == uuid.Nil {
		lastNode = firstNode
	} else {
		pointer2 = loadFileNode(firstNode.Last, curFileStruct.RootMac, curFileStruct.RootEnc, firstNode.Lastcounter)
		if pointer2 == nil {
			return errors.New(strings.ToTitle("File access not granted"))
		}
		lastNode = *pointer2
	}

	// first we need to check if the current last node has more space to write
	index := 0
	if len(lastNode.Data) < blocksize {
		end := blocksize - len(lastNode.Data)
		if end > len(content) {
			end = len(content)
			// if this is the case then we don't need to write any more to end of file. find a way to make function
			// return after this
		}
		slice := content[0:end]
		index += len(slice)
		lastNode.Data = concatenateByteArrays(lastNode.Data, slice)
		// if len > 50: something is wrong with my code. if len < 50 that means that there is no more content to append
		// and we don't need to create any new nodes
		if len(lastNode.Data) > blocksize {
			return errors.New(strings.ToTitle("need to fix implementation"))
		} else if len(lastNode.Data) < blocksize {
			lastMac, err := userlib.HashKDF(curFileStruct.RootMac, []byte("mac-key"+strconv.Itoa(firstNode.Lastcounter)))
			if err != nil {
				return errors.New(strings.ToTitle("ERROR"))
			}
			lastSym, err := userlib.HashKDF(curFileStruct.RootEnc, []byte("enc-key"+strconv.Itoa(firstNode.Lastcounter)))
			if err != nil {
				return errors.New(strings.ToTitle("ERROR"))
			}
			byteform, _ := json.Marshal(lastNode)
			block := EncMacGen(byteform, lastSym[:16], lastMac[:16])
			userlib.DatastoreSet(firstNode.Last, block)
			return nil
		}
		if firstNode.Next == uuid.Nil {
			firstNode = lastNode
		}
	}

	prevUUID := firstNode.Last
	prevNode := lastNode
	counter := firstNode.Lastcounter

	for i := index; i < len(content); i += blocksize {
		end := i + blocksize
		if end > len(content) {
			end = len(content)
		}
		slice := content[i:end]
		macKey, err := userlib.HashKDF(curFileStruct.RootMac, []byte("mac-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		symKey, err := userlib.HashKDF(curFileStruct.RootEnc, []byte("enc-key"+strconv.Itoa(counter)))
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		newnode := filenode{
			Data: slice,
		}
		curaddress := uuid.New()
		prevNode.Next = curaddress
		byteform, _ := json.Marshal(prevNode)
		block := EncMacGen(byteform, symKey[:16], macKey[:16])
		if prevUUID != curFileStruct.First {
			userlib.DatastoreSet(prevUUID, block)
		} else {
			firstNode = prevNode
		}
		prevUUID = curaddress
		counter += 1
		prevNode = newnode
	}

	// write the last node to datastore
	lastMac, err := userlib.HashKDF(curFileStruct.RootMac, []byte("mac-key"+strconv.Itoa(counter)))
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	lastSym, err := userlib.HashKDF(curFileStruct.RootEnc, []byte("enc-key"+strconv.Itoa(counter)))
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	prevNode.Next = uuid.Nil
	byteform, _ := json.Marshal(prevNode)
	block := EncMacGen(byteform, lastSym[:16], lastMac[:16])
	userlib.DatastoreSet(prevUUID, block)

	// we need to rewrite firstNode to memory because we are updating info about the counter & the address
	// of the last node
	firstMac, err := userlib.HashKDF(curFileStruct.RootMac, []byte("mac-key"+strconv.Itoa(0)))
	if err != nil {
		return err
	}
	firstSym, err := userlib.HashKDF(curFileStruct.RootEnc, []byte("enc-key"+strconv.Itoa(0)))
	if err != nil {
		return err
	}
	firstNode.Lastcounter = counter
	firstNode.Last = prevUUID
	byteform, _ = json.Marshal(firstNode)
	block = EncMacGen(byteform, firstSym[:16], firstMac[:16])
	userlib.DatastoreSet(curFileStruct.First, block)
	return nil
}

// helper method to load filestruct struct from datastore
func (userdata *User) loadFileStruct(filename string) (*filestruct, bool) {

	storageKey := filestructKeyGen(userdata.Username, filename)
	fileJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, false
	}
	// first step: verify and decrypt the filestruct
	filestructBytes, err := VerifyDec(fileJSON, userdata.FilestructEnc, userdata.FilestructMac)
	if err != nil {
		return nil, false
	}
	var curFileStruct filestruct
	err = json.Unmarshal(filestructBytes, &curFileStruct)
	if err != nil {
		return nil, false
	}
	if curFileStruct.First == uuid.Nil && curFileStruct.RootMac == nil && curFileStruct.RootEnc == nil {
		var curShareStruct sharestruct
		err = json.Unmarshal(filestructBytes, &curShareStruct)
		if err != nil {
			return nil, true
		}
		if curShareStruct.F == uuid.Nil && curShareStruct.M == nil && curShareStruct.E == nil {
			return nil, true
		}
		pointer := loadFileStruct2(curShareStruct.F, curShareStruct.E, curShareStruct.M)
		if pointer == nil {
			return nil, true
		}
		return pointer, true
	}
	return &curFileStruct, false
}

// helper method to load filestruct struct from datastore
func loadFileStruct2(storageKey uuid.UUID, encKey []byte, macKey []byte) *filestruct {
	fileJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil
	}
	// first step: verify and decrypt the filestruct
	filestructBytes, err := VerifyDec(fileJSON, encKey, macKey)
	if err != nil {
		return nil
	}
	var curFileStruct filestruct
	err = json.Unmarshal(filestructBytes, &curFileStruct)
	if err != nil {
		return nil
	}
	return &curFileStruct
}

// helper method to load a filenode struct from datastore
func loadFileNode(address uuid.UUID, rootMac []byte, rootEnc []byte, counter int) *filenode {
	ciphertext, ok := userlib.DatastoreGet(address)
	if !ok {
		return nil
	}
	macKey, err := userlib.HashKDF(rootMac, []byte("mac-key"+strconv.Itoa(counter)))
	if err != nil {
		return nil
	}
	symKey, err := userlib.HashKDF(rootEnc, []byte("enc-key"+strconv.Itoa(counter)))
	if err != nil {
		return nil
	}
	nodebytes, err := VerifyDec(ciphertext, symKey[:16], macKey[:16])
	if err != nil {
		return nil
	}
	var curnode filenode
	err = json.Unmarshal(nodebytes, &curnode)
	if err != nil {
		return nil
	}
	return &curnode
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return nil, errors.New(strings.ToTitle("ERROR"))
	}
	pointer, _ := userdata.loadFileStruct(filename)
	if pointer == nil {
		return nil, errors.New(strings.ToTitle("Access not granted"))
	}
	curFileStruct := *pointer
	if &curFileStruct == nil {
		return nil, errors.New(strings.ToTitle("ERROR"))
	}
	counter := 0
	pointer2 := loadFileNode(curFileStruct.First, curFileStruct.RootMac, curFileStruct.RootEnc, counter)
	if pointer2 == nil {
		return nil, errors.New(strings.ToTitle("ERROR"))
	}
	curnode := *pointer2
	if err != nil {
		return nil, errors.New(strings.ToTitle("verification failed"))
	}
	filebytes := curnode.Data
	for {
		if curnode.Next == uuid.Nil {
			break
		}
		counter += 1
		curnode = *loadFileNode(curnode.Next, curFileStruct.RootMac, curFileStruct.RootEnc, counter)
		if &curnode == nil {
			return nil, errors.New(strings.ToTitle("verification failed"))
		}
		filebytes = concatenateByteArrays(filebytes, curnode.Data)
	}
	return filebytes, nil
}

// helper method to load sharetree struct from datastore
func (userdata *User) loadShareTree(filename string) *sharetree {
	storageKey := generateSharetreeKey(userdata.Username, filename)
	fileJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil
	}
	// first step: verify and decrypt the filestruct
	sharetreeBytes, err := VerifyDec(fileJSON, userdata.SharetreeEnc, userdata.SharetreeMac)
	if err != nil {
		return nil
	}
	var curShareTree sharetree
	err = json.Unmarshal(sharetreeBytes, &curShareTree)
	if err != nil {
		return nil
	}
	return &curShareTree
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
	}

	pointer, shared := userdata.loadFileStruct(filename)
	if pointer == nil {
		return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
	}

	curFileStruct := *pointer
	var shareInvite sharestruct
	if shared {
		storageKey := filestructKeyGen(userdata.Username, filename)
		encryptedShared, _ := userlib.DatastoreGet(storageKey)
		sharedbytes, _ := VerifyDec(encryptedShared, userdata.FilestructEnc, userdata.FilestructMac)
		err := json.Unmarshal(sharedbytes, &shareInvite)
		if err != nil {
			return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
		}
	} else {
		newMacKey := userlib.RandomBytes(16)
		newEncKey := userlib.RandomBytes(16)
		filestructBytes, err := json.Marshal(curFileStruct)
		if err != nil {
			return uuid.Nil, err
		}
		toStore := EncMacGen(filestructBytes, newEncKey, newMacKey)
		filestructUUID := uuid.New()
		userlib.DatastoreSet(filestructUUID, toStore)
		shareInvite.E = newEncKey
		shareInvite.M = newMacKey
		shareInvite.F = filestructUUID

		// initialize the file's sharetree if it doesn't exist
		// for the future: need to account for the case where a non-owner shares this file (then no changes
		// need to be made at all to the file sharetree)
		sharetreeKey := generateSharetreeKey(userdata.Username, filename)
		_, ok := userlib.DatastoreGet(sharetreeKey)
		var shareTree sharetree
		if ok {
			pointer3 := userdata.loadShareTree(filename)
			if pointer3 == nil {
				return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
			}
			shareTree = *pointer3

		} else {
			sShareMap := make(map[string]uuid.UUID)
			sFileMap := make(map[uuid.UUID][][]byte)
			shareTree.Filemap = sFileMap
			shareTree.Sharemap = sShareMap
		}
		shareTree.Sharemap[recipientUsername] = filestructUUID
		shareTree.Filemap[filestructUUID] = [][]byte{newEncKey, newMacKey}
		storeBytes, _ := json.Marshal(shareTree)
		encryptedStore := EncMacGen(storeBytes, userdata.SharetreeEnc, userdata.SharetreeMac)
		userlib.DatastoreSet(sharetreeKey, encryptedStore)
	}

	sharestructBytes, err := json.Marshal(shareInvite)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
	}
	recipientPKE, ok := userlib.KeystoreGet(recipientUsername + "shareenc")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
	}
	storeInvite, err := userlib.PKEEnc(recipientPKE, sharestructBytes)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("ERROR"))
	}
	userSign, err := userlib.DSSign(userdata.SharePrivateKeySign, storeInvite)
	storeThis := concatenateByteArrays(storeInvite, userSign)
	shareUUID := uuid.New()
	userlib.DatastoreSet(shareUUID, storeThis)

	return shareUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	encryptedInvite, ok := userlib.DatastoreGet(invitationPtr)

	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}

	if !ok {
		return errors.New(strings.ToTitle("ERROR"))
	}
	DSVerifyKey, ok := userlib.KeystoreGet(senderUsername + "sharesign")
	if !ok {
		return errors.New(strings.ToTitle("ERROR"))
	}
	sig := encryptedInvite[len(encryptedInvite)-256:]
	message := encryptedInvite[:(len(encryptedInvite))-256]
	err := userlib.DSVerify(DSVerifyKey, message, sig)
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	shareBytes, err := userlib.PKEDec(userdata.SharePrivateKeyEnc, message)
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	var shareInvite sharestruct
	err = json.Unmarshal(shareBytes, &shareInvite)
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	// retrieve the filestruct
	_, ok = userlib.DatastoreGet(shareInvite.F)
	if !ok {
		return errors.New(strings.ToTitle("ERROR"))
	}
	// make sure that the current user does not contain a file of the same name
	putUUID := filestructKeyGen(userdata.Username, filename)
	_, ok = userlib.DatastoreGet(putUUID)
	if ok {
		return errors.New(strings.ToTitle("User already has a file of this name"))
	}

	// put the sharestruct where the file would be in datastore
	putThis := EncMacGen(shareBytes, userdata.FilestructEnc, userdata.FilestructMac)
	userlib.DatastoreSet(putUUID, putThis)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// retrieve the file sharetree
	if userdata == nil || userdata.Username == "" || userdata.FilestructMac == nil || userdata.FilestructEnc == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	sharetreeKey := generateSharetreeKey(userdata.Username, filename)
	_, ok := userlib.DatastoreGet(sharetreeKey)
	var shareTree sharetree
	if !ok {
		return errors.New(strings.ToTitle("ShareTree structure not found"))
	}
	// load the sharetree and remove the revoked user from the sharetree
	pointer3 := userdata.loadShareTree(filename)
	if pointer3 == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	shareTree = *pointer3
	revokeUUID := shareTree.Sharemap[recipientUsername]
	// below: double check that I'm using the right keys
	userlib.DatastoreDelete(revokeUUID)
	delete(shareTree.Sharemap, recipientUsername)
	delete(shareTree.Filemap, revokeUUID)

	// reencrypt the file
	filestructKey := filestructKeyGen(userdata.Username, filename)
	filecontent, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	oldpointer, _ := userdata.loadFileStruct(filename)
	if oldpointer == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	oldFileStruct := *oldpointer
	oldFirst := loadFileNode(oldFileStruct.First, oldFileStruct.RootMac, oldFileStruct.RootEnc, 0)
	var toDelete []uuid.UUID
	toDelete = append(toDelete, oldFileStruct.First)
	prevNode := oldFirst
	for i := 0; i < oldFirst.Lastcounter; i++ {
		if prevNode == nil || prevNode.Next == uuid.Nil {
			break
		}
		toDelete = append(toDelete, prevNode.Next)
		prevNode = loadFileNode(prevNode.Next, oldFileStruct.RootMac, oldFileStruct.RootEnc, i)
	}
	for i := 0; i < len(toDelete); i++ {
		userlib.DatastoreDelete(toDelete[i])
	}
	userlib.DatastoreDelete(filestructKey)
	err = userdata.StoreFile(filename, filecontent)
	newpointer, _ := userdata.loadFileStruct(filename)
	if newpointer == nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	newFileStruct := *newpointer
	if err != nil {
		return errors.New(strings.ToTitle("ERROR"))
	}
	for structUUID, keys := range shareTree.Filemap {
		encryptedBytes, ok := userlib.DatastoreGet(structUUID)
		if !ok {
			return err
		}
		structBytes, err := VerifyDec(encryptedBytes, keys[0], keys[1])
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		var curStruct filestruct
		err = json.Unmarshal(structBytes, &curStruct)
		if err != nil {
			return errors.New(strings.ToTitle("ERROR"))
		}
		curStruct.First = newFileStruct.First
		curStruct.RootMac = newFileStruct.RootMac
		curStruct.RootEnc = newFileStruct.RootEnc
		newBytes, err := json.Marshal(curStruct)
		newEncryption := EncMacGen(newBytes, keys[0], keys[1])
		userlib.DatastoreSet(structUUID, newEncryption)
	}
	return nil
}
