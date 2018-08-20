/*
**
** ascii art from: http://www.asciiworld.com
*/

import java.io.*;
import javax.imageio.*;
import java.awt.image.*;
import java.util.*;

public class stego{

  public static final List<String> EXT = Collections.unmodifiableList(
    Arrays.asList(".bmp"));
  public static final List<String> ENCRYPTION = Collections.unmodifiableList(
    Arrays.asList("AES"));

  public static boolean find_file(String file){
    File f;
    f=new File(file);
    if(!f.exists()){
      return false;
    }
    return true;
  }

  public static boolean valid_extension(String file){
    int i;
    boolean result=false;
    for(i=0;i<EXT.size();i++){
      if(file.endsWith(EXT.get(i))){
        result=true;
      }
    }
    return result;
  }

  public static void usage(){

  }

  public static void manual(){

  }

  public static void errorMessage(String error){
    System.out.println(error);
    System.exit(-1);
  }

  public static void main(String[] args){
    String img="",inp="",out="",pswd="",type="";
    int cont=0;
    boolean decrypt=false;
    BitInputStream bits;
    while(cont<args.length){
      switch (args[cont]){
        case "-f":          //filename of the image where we hide files or decrypt files
          if(find_file(args[cont+1])){
            img=args[cont+1];
          }
          cont+=2;
          break;
        case "-i":          //filename of the file we're going to hide, only encryption
          inp=args[cont+1];
          cont+=2;
          break;
        case "-o":          //filename of the output with the file with hidden info
          out=args[cont+1];
          cont+=2;
          break;
        case "-p":          //secret word
          pswd=args[cont+1];
          cont+=2;
          break;
        case "-t":          //encryption type
          type=args[cont+1];
          cont+=2;
          break;
        case "-d":          //decrypting
          decrypt=true;
          cont++;
          break;
        case "-h":          //help manual
          manual();
          System.exit(0);
          break;
        default:
          errorMessage("Error please refer to usage.");
          break;
      }
    }
  if(decrypt==false){
    if(img.isEmpty() || out.isEmpty() || inp.isEmpty()){
      errorMessage("Encryption mode error: Input file, Output file or Image not set.");
    } else {
      boolean result = image_proc.readTiles(img);
      System.out.println("Result: " + result);
    }
  } else {

  }

}
}
