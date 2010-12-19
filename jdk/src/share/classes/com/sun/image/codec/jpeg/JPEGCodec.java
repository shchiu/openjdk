/* JPEGCodec.java -- 
   Copyright (C) 2007 Free Software Foundation, Inc.
   Copyright (C) 2007 Matthew Flaschen

   This file is part of GNU Classpath.

   GNU Classpath is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   GNU Classpath is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Classpath; see the file COPYING.  If not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA.

   Linking this library statically or dynamically with other modules is
   making a combined work based on this library.  Thus, the terms and
   conditions of the GNU General Public License cover the whole
   combination.

   As a special exception, the copyright holders of this library give you
   permission to link this library with independent modules to produce an
   executable, regardless of the license terms of these independent
   modules, and to copy and distribute the resulting executable under
   terms of your choice, provided that you also meet, for each linked
   independent module, the terms and conditions of the license of that
   module.  An independent module is a module which is not derived from
   or based on this library.  If you modify this library, you may extend
   this exception to your version of the library, but you are not
   obligated to do so.  If you do not wish to do so, delete this
   exception statement from your version. */

package com.sun.image.codec.jpeg;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.awt.image.BufferedImage;
import java.awt.image.Raster;

import javax.imageio.*;
import javax.imageio.stream.*;
import javax.imageio.plugins.jpeg.*;

import java.util.Iterator;

public class JPEGCodec
{

	public static JPEGImageDecoder createJPEGDecoder(InputStream is)
	{
		return new ImageIOJPEGImageDecoder(is);
	}

	public static JPEGImageEncoder createJPEGEncoder(OutputStream os)
	{
		return null;
	}

	public static JPEGImageDecoder createJPEGDecoder(InputStream src, JPEGDecodeParam jdp)
	{
		return null; 
	}
        
	public static JPEGImageEncoder createJPEGEncoder(OutputStream dest, JPEGEncodeParam jep)
	{
		return null;
	}
        
	public static JPEGEncodeParam getDefaultJPEGEncodeParam(BufferedImage bi)
	{
		return null;
	}
        
	public static JPEGEncodeParam getDefaultJPEGEncodeParam(int numBands, int colorID)
	{
		return null;
	}
		
	public static JPEGEncodeParam getDefaultJPEGEncodeParam(JPEGDecodeParam jdp)
	{
		return null;
	}
        
	public static JPEGEncodeParam getDefaultJPEGEncodeParam(Raster ras, int colorID)
	{
		return null;
	}
        

	private static class ImageIOJPEGImageDecoder implements JPEGImageDecoder
	{
		
		private static final String JPGMime = "image/jpeg";
    
		private ImageReader JPGReader;
		
		private InputStream in;
		
		private ImageIOJPEGImageDecoder (InputStream newIs)
		{
			in = newIs;
			
			Iterator<ImageReader> JPGReaderIter = ImageIO.getImageReadersByMIMEType(JPGMime);
			if(JPGReaderIter.hasNext())
			{
				JPGReader  = JPGReaderIter.next();
			}
			
			JPGReader.setInput(new MemoryCacheImageInputStream(in));
		}

		public BufferedImage decodeAsBufferedImage() throws IOException, ImageFormatException
		{
			return JPGReader.read(0);
		}
		
		public Raster decodeAsRaster() throws IOException, ImageFormatException
		{
			return JPGReader.readRaster(0, null);
		}
		
		public InputStream getInputStream()
		{
			return in;
		}
		
		public JPEGDecodeParam getJPEGDecodeParam()
		{
			return null;
		}

		public void setJPEGDecodeParam(JPEGDecodeParam jdp)
		{
			return;
		}

	}
}
