using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Login_Server
{
    class Login_Server
    {
        SocketPermission permission;
        Socket sListener;
        IPEndPoint ipEndPoint;
        Socket handler;

        public void Load()
        {
            Console.Title = "Ferentus Login Server";
            try
            {
                // Creates one SocketPermission object for access restrictions
                SocketPermission permission = new SocketPermission(
                NetworkAccess.Accept,     // Allowed to accept connections 
                TransportType.Tcp,        // Defines transport types 
                "",                       // The IP addresses of local host 
                SocketPermission.AllPorts // Specifies all ports 
                );

                // Listening Socket object 
                Socket sListener = null;

                // Ensures the code to have permission to access a Socket 
                permission.Demand();

                // Resolves a host name to an IPHostEntry instance 
                IPHostEntry ipHost = Dns.GetHostEntry("");

                // Gets first IP address associated with a localhost 
                IPAddress ipAddr = IPAddress.Parse("0.0.0.0");

                // Creates a network endpoint 
                IPEndPoint ipEndPoint = new IPEndPoint(ipAddr, 29000);

                // Create one Socket object to listen the incoming connection 
                sListener = new Socket(
                    ipAddr.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp
                    );

                // Associates a Socket with a local endpoint 
                sListener.Bind(ipEndPoint);

                // Places a Socket in a listening state and specifies the maximum 
                // Length of the pending connections queue 
                sListener.Listen(100);

                // Begins an asynchronous operation to accept an attempt 
                AsyncCallback aCallback = new AsyncCallback(AcceptCallback);
                sListener.BeginAccept(aCallback, sListener);

                Console.WriteLine("Server is now listening on " + ipEndPoint.Address + " port: " + ipEndPoint.Port);
                Console.ReadKey();
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.ToString());
                Console.ReadKey();
            }
        }
        public void AcceptCallback(IAsyncResult ar)
        {
            Socket listener = null;

            // A new Socket to handle remote host communication 
            Socket handler = null;
            try
            {
                // Receiving byte array 
                byte[] buffer = new byte[1024];
                // Get Listening Socket object 
                listener = (Socket)ar.AsyncState;
                // Create a new socket 
                handler = listener.EndAccept(ar);

                // Using the Nagle algorithm 
                handler.NoDelay = false;

                // Creates one object array for passing data 
                object[] obj = new object[2];
                obj[0] = buffer;
                obj[1] = handler;

                // Begins to asynchronously receive data 
                handler.BeginReceive(
                    buffer,        // An array of type Byt for received data 
                    0,             // The zero-based position in the buffer  
                    buffer.Length, // The number of bytes to receive 
                    SocketFlags.None,// Specifies send and receive behaviors 
                    new AsyncCallback(ReceiveCallback),//An AsyncCallback delegate 
                    obj            // Specifies infomation for receive operation 
                    );

                // Begins an asynchronous operation to accept an attempt 
                AsyncCallback aCallback = new AsyncCallback(AcceptCallback);
                listener.BeginAccept(aCallback, listener);
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.ToString());
                Console.ReadKey();
            }
        }
        public void ReceiveCallback(IAsyncResult ar)
        {
            try
            {
                // Fetch a user-defined object that contains information 
                object[] obj = new object[2];
                obj = (object[])ar.AsyncState;

                // Received byte array 
                byte[] buffer = (byte[])obj[0];

                // A Socket to handle remote host communication. 
                handler = (Socket)obj[1];


                // The number of bytes received. 
                int bytesRead = handler.EndReceive(ar);

                if (bytesRead > 0)
                {
                    string content = BitConverter.ToString(buffer).Replace("-", " ").Substring(0, bytesRead * 3 - 1);

                    Console.WriteLine("Read " + bytesRead.ToString() + " bytes from client: " + content);

                    int length = buffer[1];
                    byte[] bytes = new byte[length];
                    Array.Copy(buffer, 2, bytes, 0, length);
                    bytes = decode(bytes);
                    content = BitConverter.ToString(bytes).Replace("-", " ");
                    Console.WriteLine("Decoded " + length.ToString() + " bytes from client: " + content);

                    if (bytes.Length >= 2)
                    {
                        // Op-Code 1 -  Login Request
                        if (bytes[0] == 0x00 & bytes[1] == 0x01)
                        {
                            byte[] username_bytes = new byte[16];
                            Array.Copy(bytes, 2, username_bytes, 0, 16);
                            username_bytes = Split(0x00, username_bytes);
                            String username = Encoding.Default.GetString(username_bytes);

                            byte[] password_bytes = new byte[16];
                            Array.Copy(bytes, 18, password_bytes, 0, 16);
                            password_bytes = Split(0x00, password_bytes);
                            String password = Encoding.Default.GetString(password_bytes);

                            byte[] version_bytes = new byte[4];
                            Array.Copy(bytes, 34, version_bytes, 0, 4);

                            Console.WriteLine("Login Request: username=" + username + " password=" + password + " client_version=" + BitConverter.ToString(version_bytes).Replace("-", "."));

                            int[] accountIDs = { 32, 48 };
                            String[] accountnames = { "rbb138", "test" };
                            String[] passwords = { "password", "test" };
                            byte[] version = { 0x00, 0x04, 0x05, 0x00 };
                            byte returncode;

                            if (BitConverter.ToInt32(version_bytes, 0) == BitConverter.ToInt32(version, 0))
                                if (accountnames.Contains(username))
                                    if (passwords.Contains(password))
                                        returncode = 0x01; //more checks for already logged in and banned users here
                                    else
                                        returncode = 0x04;
                                else
                                    returncode = 0x03;
                            else
                                if (BitConverter.ToInt32(version_bytes, 0) < BitConverter.ToInt32(version, 0))
                                    returncode = 0x02;
                                else
                                    returncode = 0x07;

                            byte[] payload = { 0x00, 0x00, returncode, 0x00 };
                            byte[] returnpacket = { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, };
                            Console.WriteLine("Sent " + returnpacket.Length + " bytes to Client: " + BitConverter.ToString(returnpacket).Replace("-", " ").Substring(0, 6) + BitConverter.ToString(payload).Replace("-", " "));
                            Array.Copy(encode(payload), 0, returnpacket, 2, payload.Length);

                            handler.BeginSend(returnpacket, 0, returnpacket.Length, 0,
                            new AsyncCallback(SendCallback), handler);
                        }

                        // UnKnown - zone request?
                        else if (bytes.Length >= 3)
                        {
                            if (bytes[0] == 0x92 & bytes[1] == 0x42 & bytes[2] == 0xC4)
                            {
                                byte[] payload = { 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                byte[] returnpacket = { 0x00, (byte)payload.Length, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                Array.Copy(encode(payload), 0, returnpacket, 2, payload.Length);
                                Console.WriteLine("Sent " + returnpacket.Length + " bytes to Client: " + BitConverter.ToString(returnpacket).Replace("-", " ").Substring(0, 6) + BitConverter.ToString(payload).Replace("-", " "));
                                handler.BeginSend(returnpacket, 0, returnpacket.Length, 0,
                                new AsyncCallback(SendCallback), handler);
                            }
                        }
                    }
                }
                    handler.BeginReceive(
                        buffer,        // An array of type Byt for received data 
                        0,             // The zero-based position in the buffer  
                        buffer.Length, // The number of bytes to receive 
                        SocketFlags.None,// Specifies send and receive behaviors 
                        new AsyncCallback(ReceiveCallback),//An AsyncCallback delegate 
                        obj            // Specifies infomation for receive operation 
                        );
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.ToString());
                Console.ReadKey();
            }
        }
        public void SendCallback(IAsyncResult ar)
        {
            try
            {
                // A Socket which has sent the data to remote host 
                Socket handler = (Socket)ar.AsyncState;

                // The number of bytes sent to the Socket 
                int bytesSend = handler.EndSend(ar);
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.ToString());
            }
        }
        private byte[] encode(byte[] bytes)
        {
            byte[] key = { 0x63, 0x3D, 0x4C, 0xB7 };
            for(int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)(bytes[i] ^ key[i % 4]);
            }
            return bytes;
        }
        private byte[] decode(byte[] bytes)
        {
            byte[] key = { 0xCD, 0x18, 0x3E, 0x0D, };
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)(key[i % 4] ^ bytes[i]);
            }
            return bytes;
        }
        private byte[] Split(byte SplitByte, byte[] buffer)
        {
            int i;
            for (i = 0; i < buffer.Length; i++)
            {
                if (buffer[i] == SplitByte)
                {
                    int offset = i;
                    break;
                }
            }
            byte[] bytes = new byte[i];
            Array.Copy(buffer, 0, bytes, 0, i);
            return bytes;
        }
    }
}
