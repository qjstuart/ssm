# **Software Security Module (SSM)**

## Running
- Install NodeJS: https://nodejs.org/en/
- Install dependencies <br>

        $ cd cryptographyssm
        $ npm install
- From `/www` add `localhost.crt` as a trusted root authority in your browser    

- Start the SSM server <br>
        
        $ npm start
        [+] Server started on port 3000.
- Generate a valid 2-part master key <a href='https://www.browserling.com/tools/random-hex'>here</a>
- Navigate to the SSM frontend at https://localhost:3000/
- Initialize the SSM and vault file by creating an application key

<br>
Administer the SSM using the 2-part master key, and encrypt/decrypt data using the application API. Keep an eye on the terminal which shows encryption/decryption steps and time taken in milliseconds

<br>
<br>

From *Applied Cryptography* (CPS3232) of the <a href='https://www.um.edu.mt/courses/overview/UBSCHICGCFT-2020-1-O'>B.Sc. Computer Science course.</a>

