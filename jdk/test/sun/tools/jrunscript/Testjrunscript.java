/*
 * Copyright 2009 Red Hat, Inc. All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */
 

/*
@test
@bug 6265810 6705893
@build CheckEngine
@run main Testjrunscript
@summary Test that output of 'jrunscript' interactive matches the expected output
*/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;



class OutputMismatchException extends RuntimeException {

    private String actualLine;
    private String expectedLine;

    public OutputMismatchException(String actualLine, String expectedLine) {
        this.expectedLine = expectedLine;
        this.actualLine = actualLine;
    }

    public String toString() {
        return "Output mismatch:\n" + "Expected: " + expectedLine + "\n"
                + "Got     : " + actualLine;
    }

};

public class Testjrunscript {

    public static final String[] jrunscriptInput = new String[] {
            "v = 2 + 5;",
            "v *= 5;",
            "v = v + \" is the value\";",
            "if (v != 0) { println('yes v != 0'); }",
            "java.lang.System.out.println('hello world from script');",
            "new java.lang.Runnable() { run: function() { println('I am runnable'); }}.run();" };

    public static final String INTERPRETER_PROMPT = "js> ";

    public static final String[] expectedOutput = new String[] {
            INTERPRETER_PROMPT + "7.0", 
            INTERPRETER_PROMPT + "35.0",
            INTERPRETER_PROMPT + "35 is the value",
            INTERPRETER_PROMPT + "yes v != 0",
            INTERPRETER_PROMPT + "hello world from script",
            INTERPRETER_PROMPT + "I am runnable", 
            INTERPRETER_PROMPT, };

    public static final double EPSILON = 0.000001;

    /**
     * Compares the expected output as stored in expectedOutput against the
     * actual output read in from processOutput
     * 
     * @param processOutput
     * @throws IOException
     */
    private static void checkOutput(InputStream processOutput)
            throws IOException {

        BufferedReader lineReader = new BufferedReader(new InputStreamReader(
                processOutput));

        String actualLine;
        String expectedLine;
        for (int i = 0; i < expectedOutput.length; i++) {
            expectedLine = expectedOutput[i];
            actualLine = lineReader.readLine();
            if (actualLine == null) {
                throw new OutputMismatchException("", expectedLine);
            }
            checkLinesMatch(actualLine, expectedLine);
        }

        actualLine = lineReader.readLine();
        if (actualLine != null) {
            throw new OutputMismatchException(actualLine, "");
        }
    }

    /**
     * Compares two lines and throws {@link OutputMismatchException} if they
     * dont match. Allows for different representations of numbers.
     * 
     * @param actualLine
     *            the actual output
     * @param expectedLine
     *            the expected output
     */
    private static void checkLinesMatch(String actualLine, String expectedLine) {
        String delimiter = "[ ]+";
        String[] actualTokens = actualLine.split(delimiter);
        String[] expectedTokens = expectedLine.split(delimiter);
        if (actualTokens.length != expectedTokens.length) {
            throw new OutputMismatchException(actualLine, expectedLine);
        }

        String actualToken;
        String expectedToken;
        for (int i = 0; i < expectedTokens.length; i++) {
            actualToken = actualTokens[i];
            expectedToken = expectedTokens[i];
            if (actualToken.equals(expectedToken)) {
                continue;
            }

            // if tokens dont match exactly, try converting them both to doubles
            // and then comparing. some versions of rhino return int for some
            // operations, while others return floats/doubles
            try {
                Double actualDouble = Double.valueOf(actualToken);
                Double expectedDouble = Double.valueOf(expectedToken);
                if (Math.abs(expectedDouble - actualDouble) < EPSILON) {
                    continue;
                } else {
                    throw new OutputMismatchException(actualLine, expectedLine);
                }
            } catch (NumberFormatException nfe) {
                throw new OutputMismatchException(actualLine, expectedLine);
            }
        }

    }

    /**
     * @return the path to the jrunscript binary
     */
    public static String getPathToJrunscript() throws FileNotFoundException {

        File jreDir = new File(System.getProperty("java.home"));
        if (!jreDir.isDirectory()) {
            throw new RuntimeException("java.home doesnt point to a directory");
        }

        String jdkDir = jreDir.getParent();
        String pathToJrunscript = jdkDir + File.separatorChar + "bin"
                + File.separatorChar + "jrunscript";
        File jrunscriptBinary = new File(pathToJrunscript);
        if (!jrunscriptBinary.exists()) {
            throw new FileNotFoundException("File "
                    + jrunscriptBinary.getAbsolutePath());
        }
        return pathToJrunscript;

    }

    /**
     * Runs the given command to execute jrunscript and checks to make sure it
     * works
     */
    public static void checkJrunscript(List<String> command) throws IOException {
        System.out.print("Testing jrunscript:");
        for (String cmd : command) {
            System.out.print(" " + cmd);
        }
        System.out.println();
        
        
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process jrunscript = pb.start();

        InputStream input = jrunscript.getInputStream();
        String inputLine;
        for (int i = 0; i < jrunscriptInput.length; i++) {
            inputLine = jrunscriptInput[i];
            jrunscript.getOutputStream().write(inputLine.getBytes());
            jrunscript.getOutputStream().write(new byte[] { '\n' });
        }
        jrunscript.getOutputStream().close();

        checkOutput(input);

        try {
            jrunscript.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (jrunscript.exitValue() != 0) {
            throw new RuntimeException("jrunscript failed");
        }
    }

    /**
     * test if jrunscript works properly
     */
    public static void main(String[] args) throws IOException,
            InterruptedException {

        if (CheckEngine.checkEngine() == 2) {
            System.out
                    .println("No js engine found and engine not required; test vacuously passes.");
        }

        // check jrunscript without any other args
        List<String> command = new LinkedList<String>();
        command.add(getPathToJrunscript());
        checkJrunscript(command);

        // check jrunscript -l js
        command.add("-l");
        command.add("js");
        checkJrunscript(command);

        System.out.println("Passed");

    }
}
