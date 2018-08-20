import java.util.*;
import javax.imageio.*;
import java.awt.image.*;
import java.io.*;

public class image_proc{ //size should be at least 4 times + filename

  public boolean hide(String image,String output,byte[] data){
    BufferedImage img = null;
    boolean res = false;
    int argb;
    int x,y;
    try {
        img = ImageIO.read(new File(image));
        for(x=0;x<img.getNumXTiles();x++){
          for(y=0;y<img.getNumYTiles();y++){
            argb=img.getRGB(x,y);
          }
        }
        res = true;
    } catch (IOException e) {
    return false;
  }
  return true;
}

  public String reveal(String image,String output){
    return null;
  }

  public static boolean readTiles(String image){
    BufferedImage img = null;
    int argb;
    int x,y;
    byte[] bits;
    try {
        img = ImageIO.read(new File(image));
        System.out.println("Height: "+ img.getHeight());
        System.out.println("Width: "+ img.getWidth());
        for(y=0;y<img.getHeight();y++){
          for(x=0;x<img.getWidth();x++){
            argb=img.getRGB(x,y) & 0xFFFCFCFC;
            //System.out.print(argb + " ");
            bits=bit_conversion(argb);
            System.out.print(bits[0] +"-"+ bits[1]+"-"+ bits[2]+"-"+ bits[3]+"  ");
          }
          //System.out.println("");
        }
    } catch (IOException e) {
    return false;
  }
  return true;
  }

  public static byte[] bit_conversion(int i){
	  byte byte3 = (byte)((i & 0xFF000000) >>> 24);
	  byte byte2 = (byte)((i & 0x00FF0000) >>> 16);
	  byte byte1 = (byte)((i & 0x0000FF00) >>> 8 );
	  byte byte0 = (byte)((i & 0x000000FF)       );
	  return(new byte[]{byte3,byte2,byte1,byte0});
	}

}
