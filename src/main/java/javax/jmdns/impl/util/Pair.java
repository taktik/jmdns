package javax.jmdns.impl.util;

/**
 * A simple paired value class
 */
public final class Pair<T, U> {
	public final T first;
	public final U second;

	public Pair(T first, U second) {
		this.second = second;
		this.first = first;
	}

	@Override
	public String toString() {
		return "(" + first + ", " + second + ")";
	}
}
