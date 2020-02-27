int foo (int a ) {
	if (a > 4) {
		return 5;
	}
	else
		return 6;
}

int bar (int a, int b, int c) {
	return foo(a+b+c);
}

int main() {
	return bar(3, 4, 5) + foo(3);
}
