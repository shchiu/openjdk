/*
  @test
  @bug 6721088
  @summary X11 Window sizes should be what we set them to
  @author Omair Majid <omajid@redhat.com>
  @run main TestFrameSize
 */

import java.awt.Dimension;
import java.awt.Frame;

/**
 * TestFrameSize.java
 * 
 * Summary: test that X11 Awt windows are drawn with correct sizes
 * 
 * Test fails if size of window is wrong
 */

public class TestFrameSize {

	static Dimension desiredDimensions = new Dimension(200, 200);
	static int ERROR_MARGIN = 15;
	static Frame mainWindow;

	public static void drawGui() {
		mainWindow = new Frame("");
		mainWindow.setPreferredSize(desiredDimensions);
		mainWindow.pack();
		// mainWindow.setVisible(true);

		Dimension actualDimensions = mainWindow.getSize();
		// System.out.println(desiredDimensions);
		// System.out.println(actualDimensions);
		if (Math.abs(actualDimensions.height - desiredDimensions.height) > ERROR_MARGIN) {
			throw new RuntimeException("Incorrect widow size");
		}

	}

	public static void main(String[] args) {
		try {
			drawGui();
		} finally {
			if (mainWindow != null) {
				mainWindow.dispose();
			}
		}
	}
}
