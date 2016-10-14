/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author stevefoo
 */
public class CBCSimpDES {
    
    static int [] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static int [] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    static int [] P4 = {2, 4, 3, 1};
    static int [] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    static int [] IPINVERSE = {4, 1, 3, 5, 7, 2, 8, 6};
    static int [] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    static byte [] K1 = new byte [8];
    static byte [] K2 = new byte [8];
    static String [][] S0 = {{"01", "00", "11", "10"},
                            {"11", "10", "01", "00"},
                            {"00", "10", "01", "11"},
                            {"11", "01", "11", "10"}};
    static String [][] S1 = {{"00", "01", "10", "11"},
                            {"10", "00", "01", "11"},
                            {"11", "00", "01", "00"},
                            {"10", "01", "00", "11"}};
    
    
    public static void main(String [] args){
        byte [] intVector = convertToByteArr("10101010");
        byte [] binaryKey = convertToByteArr("0111111101");
        byte [][] p = new byte [2][8];
        p[0] = convertToByteArr("11110100");
        p[1] = convertToByteArr("00001011");
        CBC(intVector, binaryKey, p);
    }
    
    private static void printArr(byte [] arr){
        for(byte b: arr){
            System.out.print(b);
        }
        System.out.println();
    }
    
    private static void CBC(byte [] intVec, byte [] binKey, byte [][] plainText){
        boolean first = true;
        int xor;
        byte [] xorVec = new byte[8];
        byte [] xorArr = new byte[8];
        keyGen(binKey);
        if(false){
            for(int i = 0 ; i < plainText.length; i++){
                    if(first){
                        first = false;
                        xor = (convertToInt(plainText[i])^convertToInt(intVec));
                        xorArr = convertToByteArr(xor, 8);
                        xorVec = simpleDES(xorArr);
                        printArr(xorVec);
                    } else {
                        xor = (convertToInt(plainText[i])^convertToInt(xorVec));
                        xorArr = convertToByteArr(xor, 8);
                        xorVec = simpleDES(xorArr);
                        printArr(xorVec);
                    }   
            }
        } else {
             for(int i = 0 ; i < plainText.length; i++){
                    if(first){
                        first = false;
                        xorArr = simpleDES(plainText[i]);
                        xor = (convertToInt(xorArr)^convertToInt(intVec));
                        xorVec= convertToByteArr(xor, 8);
                        printArr(xorVec);
                    } else {
                        xorArr = simpleDES(plainText[i]);
                        xor = (convertToInt(xorArr)^convertToInt(plainText[i-1]));
                        xorVec = convertToByteArr(xor, 8);
                        printArr(xorVec);
                    }   
            }
        
        }
    }
    
    private static byte [] simpleDES(byte [] xor){
        byte [] temp = new byte [8];
        byte [] swap = new byte [8];
        byte [] cipher = new byte[8];
        if(false){
            for(int i = 0; i < xor.length; i++){
                temp[i] = xor[IP[i]-1];            
            }
            swap = fk(temp, K1);
            temp = new byte []{swap[4], swap[5], swap[6], swap[7], swap[0], swap[1], swap[2], swap[3]};
            swap = fk(temp, K2);
            for(int i = 0; i < swap.length; i++){
                cipher[i] = swap[IPINVERSE[i]-1];            
            }
            return cipher;
        
        } else {
            for(int i = 0; i < xor.length; i++){
                temp[i] = xor[IP[i]-1];            
            }
            swap = fk(temp, K2);
            temp = new byte []{swap[4], swap[5], swap[6], swap[7], swap[0], swap[1], swap[2], swap[3]};
            swap=fk(temp, K1);
            for(int i = 0; i < swap.length; i++){
                cipher[i] = swap[IPINVERSE[i]-1];            
            }
            return cipher;
        }
    
    }
    
    private static byte [] fk(byte [] input, byte [] k){
        byte [][] half = splitArr(input);
        byte [] whole = new byte [8];
        byte [] p4 = new byte [4];
        int xor;
        byte [] xorArr = new byte [4];
      
        byte [] newHalf = f(half[1], k);
        for(int i = 0; i < 4; i++){
            p4[i]= newHalf[P4[i]-1];
        }
        xor = convertToInt(half[0])^convertToInt(p4);
        xorArr = convertToByteArr(xor, 4);
        for(int i = 0; i < whole.length; i++){
            if(i < 4){
                whole[i] = xorArr[i];
            } else{
                whole[i] = half[1][i-4];
            }
        }
        return whole;      
    }
    
    private static byte [] f(byte [] half, byte [] k){
        byte [] ep = new byte [8];
        int xor;
        int row;
        int col;
        String s0s1 = "";
        for(int i = 0 ; i < ep.length; i++){
            ep[i] = half[EP[i]-1];
        }
        xor = convertToInt(ep)^convertToInt(k);
        byte [][] xorArr = splitArr(convertToByteArr(xor, 8));
        
        row = convertToInt(new byte[]{xorArr[0][0],xorArr[0][3]});
        col = convertToInt(new byte[]{xorArr[0][1],xorArr[0][2]});
        s0s1 += S0[row][col];
        row = convertToInt(new byte[]{xorArr[1][0],xorArr[1][3]});
        col = convertToInt(new byte[]{xorArr[1][1],xorArr[1][2]});
        s0s1 += S1[row][col];
        
        return convertToByteArr(s0s1);
    
    }
    
    private static void keyGen(byte [] binKey){
        byte [] p10 = new byte [10];
        for(int i = 0; i < P10.length ; i++){
            p10[i] = binKey[P10[i]-1];
        }
        
        byte[][] half = splitArr(p10);
         
         half[0] = shift(half[0], 1);
         half[1] = shift(half[1], 1);
         
         K1 = getKey(half[0], half[1]);
         
         half[0] = shift(half[0], 2);
         half[1] = shift(half[1], 2);
         
         K2 = getKey(half[0], half[1]);
         
               
    }
    
    private static byte [] shift(byte [] arr, int move){
        byte [] buffer = new byte [2];
        byte [] temp = new byte [5];
        if(move == 1){
            buffer[0] = arr[0];
            temp = shiftLeft(arr);
            temp[4] = buffer[0];
            return temp;
            
        } else {
            buffer[0] = arr[0];
            buffer[1] = arr[1];
            temp = shiftLeft(arr);
            temp = shiftLeft(temp);
            temp[3] = buffer[0];
            temp[4] = buffer[1];
            return temp;
        }  
    }
    
    private static byte [] shiftLeft(byte [] arr){
        byte [] temp = arr;
        for(int i = 0; i < arr.length-1; i++)
            temp[i] = arr[i+1];
        return temp; 
    }
    
    private static byte [] getKey(byte [] firstHalf, byte [] secondHalf){
        byte [] p10 = new byte [10];
        byte [] p8 = new byte[8];
        byte [] temp8 = new byte[8];
        for(int i = 0; i <p10.length ;i++){
            if(i<=4){
                p10[i] = firstHalf[i];
            } else {
                p10[i]=secondHalf[i-5];
            }
         }
         
         for(int i = 0; i< p8.length; i++){
             p8[i] = p10[P8[i]-1];
         } 
         
         return p8;
    }
    
    private static byte[][] splitArr(byte [] arr){
        byte [] firstHalf = new byte[arr.length/2];
        byte [] secondHalf = new byte[arr.length/2];
        for(int i = 0; i < arr.length/2 ; i ++)
            firstHalf[i] = arr[i];
        
        for(int i = 0; i < arr.length/2 ; i ++)
            secondHalf[i] = arr[i+arr.length/2];
        
        return new byte[][]{firstHalf, secondHalf};
    
    }
    
    private static byte [] convertToByteArr(String s){
        String [] raw = s.split("");
        byte [] conversion = new byte [raw.length];
        for(int i = 0; i < raw.length; i++){
            conversion[i] = Byte.parseByte(raw[i]);         
        }
        return conversion;   
    }
    
    private static byte [] convertToByteArr(int x, int size){
        int sum = x;
        int power = size-1;
        byte [] arr = new byte [size];
        for(int i =0 ; i < size ; i++){
            if(sum / Math.pow(2, power) >= 1){
                arr[i]=1;
                sum -= Math.pow(2, power--);
            } else {
                power--;
            }
        }
        return arr;          
    }
    
    private static int convertToInt(byte [] byteArr){
        int power = byteArr.length-1;
        int sum = 0;
        for(Byte b: byteArr){
            if(b==1){
                sum += Math.pow(2, power--);
            } else {
                power--;
            }
        }
        return sum;      
    }
    
}
