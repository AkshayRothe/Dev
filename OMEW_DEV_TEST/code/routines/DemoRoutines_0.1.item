//template routine Java
package routines;

public class DemoRoutines {

  /***** 
     * helloExemple: Print the hello message on the console
     * {Category} DemoRoutine
     * {talendTypes} String
	 *
     * */	    	
    public static void helloExemple(String message) {
        if (message == null) {
            message = "World";
        }
        System.out.println("Hello "+message+" !");
    }
    
   /** 
     * getExemple: Return hello message
     * {Category} DemoRoutine
     * {talendTypes} String
	 *
     * */	    
    public static String getExemple(String message) {
        if (message == null) {
            message = "World";
        }
        return ("Hello "+message+" !");
    }

   /** 
     * getPropertiesUrl: Return the Properties URL
     * {Category} DemoRoutine
     * {talendTypes} String
	 *
     * */	
    public static String getPropertiesUrl() {
        return "http://talendforge.org/file_fetch.txt";
    }    
    
    /** 
     * getLabel: Return a label 
     * {Category} DemoRoutine
     * {talendTypes} String
	 *
     * */	
    public static String getLabel(int i) {
    	String message = " value > 50";
    	if(i<50) {
    		message = " value < 50";
    	}
        return message;
    } 
    
    /** 
     *DemoRoutines.getFilter(int i, int i2) return true if i < i2 and false else
     * {Category} DemoRoutine
     * {talendTypes} Boolean
	 *
     * */
    public static Boolean getFilter(int i, int i2) {
    	if(i<i2) {
    		return true;
    	}
        return false;
    } 

    
    
    
    
    
    
    
    /**
     * The following methods are commented to be usable on a tRowGenerator
     */
    
    
    /**
     * getRandomDay : Return a randomly Open Day
     * 
     * {Category} String
     * {talendTypes} String
     * 
     * {example} getRandomDay() # Monday
     */
    public static String getRandomOpenDay() {
    	String day[] = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"};
        int i = ((Long)Math.round(Math.random() * (4))).intValue();
        return day[i];
    }

    
    /**
     * getRandomName : Return a randomly Name
     * 
     * {Category} String
     * {talendTypes} String
     * 
     * {example} getRandomName() # Monday
     */
    public static String getRandomIndividu() {
    
    	String individu[] = {"Eric DUPOND", "Jean DURAND", "Michael DELAMONTAGNE", "Sophie DUPUIS", "Laure DELAFORGE", "Martin DUJARDIN", "Sylvie DUPUIT", "Corinne LILOU", "Frederique LAPTOP"};
        int i = ((Long)Math.round(Math.random() * (8))).intValue();
        return individu[i];
    }
    
    
    
    
    
    
    
    
}
