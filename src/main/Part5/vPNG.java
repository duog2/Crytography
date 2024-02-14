import java.util.*;
public class vPNG {
    private final int seed;
    private Random generator;
    public vPNG(int seed){
        this.seed = seed;
        this.generator = new Random();
    }
    public byte next() {
        return (byte) generator.nextInt(seed);
    }
}
