package routines;

public class GetRandomPhoneNum {


    /**
     * GetPhone: generates randomly a french phone number
     * 
     * 
     * {talendTypes} String
     * 
     * {Category} User Defined
     * 
     * {example} GetPhone() # 0123456789.
     */
    public static String GetPhone() {
    	String Tel="0";
    	Tel=Tel.concat(String.valueOf(Math.round(routines.Numeric.random(1,6))));
    	for(int i=0;i<8;i++){
    		Tel=Tel.concat(String.valueOf(Math.round(routines.Numeric.random(0,9))));
    	}
    	return Tel;    	

    }
    public static void main(String args[]){
    	System.out.println(GetPhone());
    }
}
