using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Login_Server
{
    class Program
    {

        static void Main(string[] args)
        {
            Login_Server instance = new Login_Server();
            instance.Load();
        }
    }
}
