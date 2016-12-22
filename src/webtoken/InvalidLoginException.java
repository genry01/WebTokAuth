package webtoken;

class InvalidLoginException extends Exception
{
    @SuppressWarnings("compatibility:-8658253352688014827")
    private static final long serialVersionUID = 4958014032204729229L;

    public InvalidLoginException()
    {
        
    }
    
    public InvalidLoginException(String exceptionMessage)
    {
        super(exceptionMessage);
    }
}
