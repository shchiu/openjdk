/*
 * Copyright 2009 Red Hat, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
  @test
  @summary Check that the final joint created using 
           generalPath.closePath() is correct
  @author Omair Majid <omajid@redhat.com>
  @run main MiterInternalCloseJointTest
 */
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.geom.GeneralPath;
import java.awt.image.BufferedImage;

public class MiterInternalCloseJointTest {

    static final int WIDTH = 200;
    static final int HEIGHT = 200;

    static final int x0 = 50, y0 = 50;
    static final int x1 = 150, y1 = 50;
    static final int x2 = 100, y2 = 100;

    private static BufferedImage createTestImage() {
        final BufferedImage image = new BufferedImage(WIDTH, HEIGHT,
                BufferedImage.TYPE_INT_BGR);
        Graphics2D g = image.createGraphics();

        g.setColor(Color.BLACK);
        g.fillRect(0, 0, WIDTH, HEIGHT);

        float wideStrokeWidth = 20.0f;
        BasicStroke wideStroke = new BasicStroke(wideStrokeWidth,
                BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, wideStrokeWidth);
        float thinStrokeWidth = 3.0f;
        BasicStroke thinStroke = new BasicStroke(thinStrokeWidth,
                BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, thinStrokeWidth);

        g.setColor(Color.WHITE);
        GeneralPath path = new GeneralPath();
        path.moveTo(x0, y0);
        path.lineTo(x1, y1);
        path.lineTo(x2, y2);
        path.closePath();
        path.closePath();
        g.setStroke(thinStroke);
        g.draw(wideStroke.createStrokedShape(path));

        return image;
    }

    public static void main(String[] args) {

        BufferedImage testImage = createTestImage();

        int color = testImage.getRGB(x0,y0-5);
        System.out.println("Color seen: #" + Integer.toHexString(color));
        if (color == Color.WHITE.getRGB()) {
            throw new RuntimeException(
                    "Test Failed; did not expected to see a white line at the start of the path");
        }

    }
}
