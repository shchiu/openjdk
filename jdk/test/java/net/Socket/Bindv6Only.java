// test for IPv6 related issues in Sun's JDK for Linux

// before running the test you need to execute
// sudo sysctl -w net.ipv6.bindv6only=1

// Author: Torsten Werner
// public domain

// Adapted for JTreg by Andrew John Hughes

/*
 * @test
 * @bug 6342561
 * @summary Socket doesn't work with net.ipv6.bindv6only turned on
 * @library ../../..
 */

import java.io.*;
import java.net.*;

public class Bindv6Only {

  public static void main(String [] args) throws IOException {
    InetAddress localAddress = null;
    InetAddress remoteAddress = null;
    localAddress = InetAddress.getByName(InetAddress.getLocalHost().getHostName());
    remoteAddress = InetAddress.getByName(TestEnv.getProperty("host"));

    int remotePort = 7;
    Socket testSocket = null;

    System.out.print("Test #1... ");
    try {
      testSocket = new Socket(remoteAddress, remotePort, localAddress, 0);
      System.out.println("passed.");
    } catch (IOException e) {
      throw new
        RuntimeException("Failed to connect from specified local address", e);
    }

    System.out.print("Test #2... ");
    try {
      testSocket = new Socket(remoteAddress, remotePort, null, 0);
      System.out.println("passed.");
    } catch (IOException e) {
      throw new RuntimeException("Failed to connect from localhost", e);
    }

    System.out.print("Test #3... ");
    try {
      testSocket = new Socket(remoteAddress, remotePort);
      System.out.println("passed.");
    } catch (IOException e) {
      throw new RuntimeException("Failed to connect from default local address and port.");
    }
  }
}
