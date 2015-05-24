package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;


public class Shamir {
	
	public static class Share{
		int x;
		BigInteger sum;
		
		public Share(int x, BigInteger sum){
			this.sum=sum;
			this.x=x;
		}

		public int getX() {
			return x;
		}

		public BigInteger getSum() {
			return sum;
		}
		
	}

	private static BigInteger getRandomLess(final BigInteger p) {
        while (true) {
            final BigInteger r = new BigInteger(p.bitLength()-(int)(Math.random()*20), new SecureRandom());
            if (r.compareTo(BigInteger.ZERO) > 0 && r.compareTo(p) < 0) {
                return r;
            }
        }
    }
	
	public static BigInteger generatePrime(BigInteger secret){
		return BigInteger.probablePrime(secret.bitLength()+1+(int)(Math.random()*20), new SecureRandom());
	}
	
	public static Share[] split(BigInteger number, int available, int  needed,BigInteger prime) {
		BigInteger[] coef = new BigInteger[needed];
		Share[] shares = new Share[available];
		coef[0]=number;
		for(int i=1;i<needed;i++)
			coef[i]=getRandomLess(prime);
	    for(int x = 1; x <= available; x++) {
	    	BigInteger sum = coef[0];
	        for(int j = 1; j < needed; j++) 
	        	sum = sum.add(coef[j].multiply(BigInteger.valueOf((long)Math.pow(x, j))).mod(prime)).mod(prime);
	        shares[x - 1] = new Share(x, sum);
	    }
	    return shares;
	}
	 
	public static BigInteger join(Share[] shares,BigInteger prime,int needed) {
		int formulaLength,count;
		BigInteger sum = BigInteger.ZERO,numerator,denominator,startposition, nextposition,value,tmp;
	    for(formulaLength =  0; formulaLength < shares.length && formulaLength<needed; formulaLength++) {
	    	numerator = BigInteger.ONE;
	    	denominator = BigInteger.ONE;
	        for(count = 0; count < shares.length && count<needed; count++) {
	            if(formulaLength == count) continue; 
	            startposition = BigInteger.valueOf(shares[formulaLength].x);
	            nextposition = BigInteger.valueOf(-shares[count].x);
	            numerator = (numerator.multiply(nextposition)).mod(prime);
	            denominator = (denominator.multiply(startposition.add(nextposition))).mod(prime);
	        }
	        value = shares[formulaLength].sum;
	        tmp = (value.multiply(numerator).multiply(denominator.modInverse(prime))).mod(prime);
	        sum=sum.add(tmp).mod(prime);
	    }
	    return sum;
	}
}
