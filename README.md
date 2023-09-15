# Design Doc & Proper Usage Scenarios

## User Authentication

### How are users authenticated?
- The User struct is encrypted and signed symmetrically in Datastore using the
  user’s password. Impossible to login without knowing the username and
  password.
### What information is stored in Datastore/Keystore for each user?
- Keystore: store a PKE Enc/Dec key pair for sending and receiving share (publicly
  encrypted) invites
- Keystore: store a DSVerifyKey/DSSignKey, for verifying the integrity of share
  invites
- Datastore: an instance of the User struct for that particular user with the
  appropriate member information

### How can a user have multiple client instances (e.g. laptop, phone, etc.) running simultaneously?
- All of the members inside of the User struct are permanent and never need to be
  changed.
- All changes to files or new files are not stored within the User struct but rather
  the Datastore and can be instantly accessed across multiple client instances
  running simultaneously.
## File Storage and Retrieval

_How will a user store their files? How will a user retrieve their files from the server?_

**Alice is logged in and wants to store a file:**
1. create a new filestruct()
2. enc and mac it using the user’s filestruct enc and mac key
3. store <UUID(hash(username) + hash(filename), enc and mac’d filestruct> in Datastore
4. put 100 bytes of file data at a time in filenodes, generate new encrypt and mac keys for
   each using HashKDF’s and a counter and IV from filestruct. Use (previous key +
   counter) as the key value for HashKDF key generation for each block.
5. put UUID of the first and last filenode in the filestruct (for efficient appending)

**Alice wants to retrieve a file:**
1. get UUID(hash(username) + hash(filename)) from the Datastore
2. verify the mac and decrypt each filenode.

**Alice wants to (efficiently) append a file:**
1. Alice loads the filestruct for the appropriate file from Datastore.
2. Alice verifies and decrypt the first filenode, which contains info about the last filenode.
   Alice then verifies and decrypt the last filenode. If it isn’t full, Alice adds some of the file
   contents that need to be appended to the end of that data.
3. Alice uses the root Mac and Enc keys to encrypt and sign the file appending and creates
   more filenodes, and attaches that to the previous last filenode.

This way we don’t need to verify and decrypt the rest of the original blocks. Only the filestruct
first node, and the last node, need to be downloaded, not any of the middle file nodes. Thus the
downloading/uploading data I/O times are not dependent at all on the current length of the file,
only the amount of data to be appended.

## File Sharing and Revocation

_How will a user share files with another user? How does this shared user access the
shared file after accepting the invitation? How will a user revoke a different user’s
access to a file? How will you ensure a revoked user cannot take any malicious actions
on a file?_

**How will Alice create the invitation to Bob and what will be stored in the invitation?**
1. Alice creates a sharestruct.
2. She encrypts it using Bob’s public key and signs it using her private signing key.
3. She puts it in (random UUID, publicly encrypted/signed sharestruct)
4. Alice generates another random UUID, a random enc key, and a random mac key
   (symmetric not public key) and generates a copy of the current filestruct.
5. Alice encrypts and macs the filestruct using these new generated keys, and puts (new
   UUID, encrypted and mac’d filestruct) in Datastore.
6. Alice creates the sharetree for the file (if it doesn’t exist) and puts it in datastore,
   encrypted and mac’d with the appropriate keys.
7. Alice adds Bob to the sharetree
8. She puts the new symmetric keys in the encrypted/signed sharestruct in Datastore.

**What happens when Bob accepts the invitation?**
1. Bob already received senderUsername and invitationPtr via a secure channel.
2. Bob does Datastore.get(invitationPtr), verifies that the value came from Alice using her
   mac public key.
3. Bob uses his private enc key to decrypt the sharestruct, and retrieves the filestruct UUID,
   mac key, and enc key from the sharestruct.
4. He then puts the sharestruct in datastore where he would have put filestruct if he owned
   the file, and he encrypts and decrypts the sharestruct with his personal filestruct mac
   and enc key.

**How will Bob access this file in the future?**

1. Bob gets hash(hash(bobusername) + hash(filename)) from Datastore. He verifies and
   decrypts it. He checks if its an instance of filestruct, which will return false. Then he
   checks if its an instance of sharestruct, which will return true.
2. He retrieves the filestruct UUID, enc key, and mac key, then he accesses the file
   normally.

**Bob is not the owner of the file, but wants to share the file with David.**
1. Bob creates his own sharestruct in the same way (signed with Bob’s private key,
   encrypted with David’s public key), but this time, instead of generating a new filestruct
   with new random symmetric keys and enc keys, he shares the info of the one he already
   has. Bob does not modify the file sharetree
2. David does everything the same as how Bob did when he accepted it.


**Alice shared the file with Bob and Charlie, and Bob shared this file with David. Now,
Alice wants to revoke Bob’s access. How can she revoke Bob’s access, what changes, if any,
needs to happen on file structs?**


- Alice retrieves the file’s sharetree. Then she goes to the filestruct she created for Bob,
   and deletes all the info, and remove’s Bob’s node.
 - Alice re-encrypts the entire file with a new root Mac key, a new root Enc key, and new
   UUID addresses for every filenode. Alice deletes the old filestruct and filenodes
   corresponding to the file.
- Then she goes through the file’s sharetree, and updates the filestructs of everyone still
   remaining with the new filenode information.

**How do we ensure that Charlie still has access to this file? How do we ensure David loses
access to this file?**

- The updated pointers and information available only for Charlie.
- David can only see the old version of the file, and cannot gain any information about any
   updates made to the file after his access was revoked.
   How do you ensure that Bob and David cannot retrieve any information about the future state of
   the file?
- Bob and David cannot access the old file data because that information has been
   deleted. Even if they saved the access data, the entire fire has been re-encrypted and
   moved to different addresses.