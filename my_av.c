// Covei Denis - 312 CA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>

#define BUFF_SIZE 10000
#define INT_MAX 2147483647

/* intoarce 1 daca deschiderea fisierului a esuat, respectic 0 daca s-a
   efectuat cu succces*/
int check_file(FILE *file, char *filename)
{
	if (!file) {
		fprintf(stderr, "Could not open %s\n", filename);
		return 1;
	}
	return 0;
}

// functiere pentru inchiderea mai multor fisiere simultan
void close_files(int files_count, ...)
{
	va_list files;
	va_start(files, files_count);

	for (int i = 0; i < files_count; i++)
		fclose(va_arg(files, FILE *));

	va_end(files);
}

// stocheaza baza de date a url-urilor malitioase deja cunoscute
int get_bad_urls(char ***bad_urls)
{
	// deschid fisierul cu baza de date a url-urilor malitioase
	char *urls_database_filename = "data/urls/domains_database";
	FILE *urls_database = fopen(urls_database_filename, "rt");
	if (check_file(urls_database, urls_database_filename))
		exit(-1);

	// initializez numarul url-urilor malitioase
	int bad_urls_count = 0;

	// citesc fiecare url malitios
	char url[BUFF_SIZE];

	while (fgets(url, BUFF_SIZE, urls_database)) {
		url[strlen(url) - 1] = '\0';
		*bad_urls = (char **)realloc(*bad_urls,
			(++bad_urls_count) * sizeof(char *));
		(*bad_urls)[bad_urls_count - 1] = strdup(url);
	}

	fclose(urls_database);

	// intorc numarul url-urilor malitioase
	return bad_urls_count;
}

int minimum(int nums_count, ...)
{
	va_list nums;
	va_start(nums, nums_count);

	int mi = INT_MAX;

	for (int i = 0; i < nums_count; i++) {
		int curr_num = va_arg(nums, int);
		if (curr_num < mi)
			mi = curr_num;
	}

	va_end(nums);

	return mi;
}

// distanta Damerau-Levenshtein (distanta optima de suprapunere)
int string_distance(char *a, char *b)
{
	int len_a = strlen(a);
	int len_b = strlen(b);

	int **d = (int **)calloc(len_a + 1, sizeof(int *));
	for (int i = 0; i <= len_a; i++)
		d[i] = (int *)calloc(len_b + 1, sizeof(int));

	for (int i = 0; i <= len_a; i++)
		d[i][0] = i;
	for (int j = 0; j <= len_b; j++)
		d[0][j] = j;

	for (int i = 1; i <= len_a; i++) {
		for (int j = 1; j <= len_b; j++) {
			int cost = 0;
			if (a[i - 1] != b[j - 1])
				cost = 1;
			d[i][j] = minimum(3, d[i - 1][j] + 1, d[i][j - 1] + 1,
							  d[i - 1][j - 1] + cost);
			if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
				d[i][j] = minimum(2, d[i][j], d[i - 2][j - 2] + 1);
		}
	}

	int distance = d[len_a][len_b];

	for (int i = 0; i <= len_a; i++)
		free(d[i]);
	free(d);

	return distance;
}

bool trusted_url(char *url)
{
	if (strstr(url, "cmd=_login-run"))
		return 1;

	if (url[0] == '\'' && url[strlen(url) - 1] == '\'')
		return 1;

	return 0;
}

bool malicious_substrings(char *url)
{
	static const char *const substrings[] = { "e=com", "cmd.login", "/exe",
											 "/bin", "signin", "admin",
											 "http://"};
	int substrings_count = sizeof(substrings) / sizeof(char *);

	for (int i = 0; i < substrings_count; i++) {
		if (strstr(url, substrings[i]))
			return 1;
	}

	char *file = strrchr(url, '/');
	if (file) {
		if (!strcmp(file, "/login"))
			return 1;
	}

	return 0;
}

bool malware_extension(char *url)
{
	static const char *const extensions[] = { ".exe", ".bin", ".jpg", ".png",
											 ".dat", ".doc", ".css", ".sh",
											 ".com", ".pdf", "jpeg", ".bat",
											 ".dz", ".run", ".pif", ".wsh",
											 ".ipa", ".osx", ".download",
											 ".spc", ".mpsl", ".x86" };
	int extensions_count = sizeof(extensions) / sizeof(char *);
	char *extension = strrchr(url, '.');

	for (int i = 0; i < extensions_count; i++) {
		if (!strcmp(extension, extensions[i]))
			return 1;
	}

	return 0;
}

bool is_in_database(char *domain, int bad_urls_count, char **bad_urls)
{
	for (int i = 0; i < bad_urls_count; i++) {
		if (!strcmp(domain, bad_urls[i]))
			return 1;
	}

	return 0;
}

bool too_many_digits(char *domain)
{
	int digits = 0;

	for (int i = 0; domain[i]; i++) {
		if (isdigit(domain[i]))
			digits++;
	}

	return (double)digits > 0.092 * strlen(domain);
}

bool malicious_www(char *domain)
{
	char *subdomain = strndup(domain, strchr(domain, '.') - domain);
	if (strstr(subdomain, "www") && strcmp(subdomain, "www")) {
		free(subdomain);
		return 1;
	}

	free(subdomain);
	return 0;
}

bool too_many_hyphens(char *domain)
{
	int hyphen_count = 0;

	for (int i = 0; domain[i]; i++) {
		if (strchr("-", domain[i]))
			hyphen_count++;
	}

	return hyphen_count >= 3;
}

bool malicious_TLD(char *domain)
{
	if (strrchr(domain, '.')) {
		char *TLD = strdup(strrchr(domain, '.'));

		static const char *const list[] = { ".ru", ".cn", ".cf", ".cc" };
		int list_count = sizeof(list) / sizeof(char *);

		for (int i = 0; i < list_count; i++) {
			if (!strcmp(TLD, list[i])) {
				free(TLD);
				return 1;
			}
		}

		free(TLD);
	}

	return 0;
}

bool too_many_dots(char *domain)
{
	int dots = 0;

	for (int i = 0; domain[i]; i++) {
		if (domain[i] == '.')
			dots++;
	}

	return dots > 3;
}

bool similar_domains(char *domain)
{
	static const char *const trusted_domains[] = { "facebook", "twitter",
						"whatsapp", "baidu", "instagram", "wikipedia",
						"google", "paypal" };
	int trusted_domains_count = sizeof(trusted_domains) / sizeof(char *);

	char copy_domain[BUFF_SIZE];
	strcpy(copy_domain, domain);
	char *tok = strtok(copy_domain, ".");

	while (tok) {
		for (int i = 0; i < trusted_domains_count; i++) {
			int distance = string_distance(tok, (char *)trusted_domains[i]);
			if (1 <= distance && distance <= 2)
				return 1;
		}
		tok = strtok(NULL, ".");
	}

	return 0;
}

// intoarce 1 daca url-ul este benign, 0 in caz contrar
bool is_benign_task1(char *url, int bad_urls_count, char **bad_urls,
					 FILE *output)
{
	// test 1 - verificare caracteristici de incredere
	if (trusted_url(url))
		return 1;

	// test 2 - cautare substring potential malitios
	if (malicious_substrings(url))
		return 0;

	// test 3 - verificarea extensiei url-ului
	if (malware_extension(url))
		return 0;

	// obtinerea domeniului
	char *domain = strndup(url, strchr(url, '/') - url);

	// test 4 - cautarea domeniului in baza de date a domeniilor malitioase
	if (is_in_database(domain, bad_urls_count, bad_urls)) {
		free(domain);
		return 0;
	}

	// test 5 - verificare numar cifre in domeniu
	if (too_many_digits(domain)) {
		free(domain);
		return 0;
	}

	// test 6 - verificare www
	if (malicious_www(domain)) {
		free(domain);
		return 0;
	}

	// test 7 - verificare aparitie simboluri in domeniu
	if (too_many_hyphens(domain)) {
		free(domain);
		return 0;
	}

	// test 8 - verificare TLD frecvent malitioase
	if (malicious_TLD(domain)) {
		free(domain);
		return 0;
	}

	// test 9 - numar subdomenii
	if (too_many_dots(domain)) {
		free(domain);
		return 0;
	}

	// test 10 - verificare domenii de incredere cu nume similare
	if (similar_domains(domain)) {
		free(domain);
		return 0;
	}

	free(domain);
	return 1;
}

void run_task1(void)
{
	char **bad_urls = (char **)malloc(sizeof(char *));
	int bad_urls_count = get_bad_urls(&bad_urls);

	// deschid fisierul cu url-uri de testat
	char *input_filename = "data/urls/urls.in";
	FILE *input = fopen(input_filename, "rt");
	if (check_file(input, input_filename))
		exit(-1);

	// deschid fisierul de output
	char *output_filename = "urls-predictions.out";
	FILE *output = fopen(output_filename, "wt");
	if (check_file(output, output_filename)) {
		fclose(input);
		exit(-1);
	}

	// citesc fiecare url care va fi verificat
	char url[BUFF_SIZE];

	while (fgets(url, BUFF_SIZE, input)) {
		url[strlen(url) - 1] = '\0';
		fprintf(output, "%d\n", !is_benign_task1(url, bad_urls_count, bad_urls,
												 output));
	}

	for (int i = 0; i < bad_urls_count; i++)
		free(bad_urls[i]);
	free(bad_urls);

	close_files(2, input, output);
}

void free_strings(int count, ...)
{
	va_list strings;
	va_start(strings, count);

	for (int i = 0; i < count; i++)
		free(va_arg(strings, char *));

	va_end(strings);
}

bool is_benign_task2(char *line, char **fields)
{
	bool benign = 1;
	bool duration_exceded = 0;
	bool safe = 0;
	int flag_count = 0;
	int count = 0;
	char *eptr;
	char *field = strtok(line, ",");

	char *seconds;
	char *minutes;
	char *hours;
	char *days;

	double time;

	while (field) {
		// parsam flow_duration
		if (!strcmp(fields[count], "flow_duration")) {
			seconds = strdup(strrchr(field, ':') + 1);
			minutes = strndup(strchr(field, ':') + 1, 2);
			hours = strndup(strchr(field, ':') - 2, 2);
			days = strndup(field, strchr(field, ' ') - field);

			time = strtod(seconds, &eptr) +
				60.0 * strtod(minutes, &eptr) +
				3600.0 * strtod(hours, &eptr) +
				86400.0 * strtod(days, &eptr);

			if (time > 0.0)
				duration_exceded = 1;
		}

		// verificare prezenta ip safe
		if (!strcmp(fields[count], "response_ip")) {
			if (!strcmp(field, "255.255.255.255") ||
				!strcmp(field, "ff02::16"))
				safe = 1;
		}

		/* bruteforce - valoare mare pentru flow_pkts_payload.avg si
						valoare mare pentru flow_duration*/
		if (!strcmp(fields[count], "flow_pkts_payload.avg")) {
			if (duration_exceded && strtod(field, &eptr) > 580.0)
				benign = 0;
		}

		/* cryptominer - au toate flag-urile nule
						 response_ip nu e safe */
		if (!strcmp(fields[count], "flow_FIN_flag_count") ||
			!strcmp(fields[count], "flow_SYN_flag_count") ||
			!strcmp(fields[count], "flow_ACK_flag_count")) {
			if (!strcmp(field, "0") && !safe)
				flag_count++;
		}
		count++;
		field = strtok(NULL, ",");
	}
	free_strings(4, seconds, minutes, hours, days);
	if (flag_count == 3)
		benign = 0;
	return benign;
}

void run_task2(void)
{
	// deschid fisierul cu url-uri de testat
	char *input_filename = "data/traffic/traffic.in";
	FILE *input = fopen(input_filename, "rt");
	if (check_file(input, input_filename))
		exit(-1);

	// deschid fisierul de output
	char *output_filename = "traffic-predictions.out";
	FILE *output = fopen(output_filename, "wt");
	if (check_file(output, output_filename)) {
		fclose(input);
		exit(-1);
	}

	char line[BUFF_SIZE];
	fgets(line, BUFF_SIZE, input);
	line[strlen(line) - 1] = '\0';

	// stocheaza numele campurilor
	int fields_count = 0;
	char **fields = malloc(0);
	char *field_name = strtok(line, ",");
	while (field_name) {
		fields = (char **)realloc(fields, (++fields_count) * sizeof(char **));
		fields[fields_count - 1] = strdup(field_name);
		field_name = strtok(NULL, ",");
	}

	// verifica fiecare site
	while (fgets(line, BUFF_SIZE, input)) {
		line[strlen(line) - 1] = '\0';
		fprintf(output, "%d\n", !is_benign_task2(line, fields));
	}

	for (int i = 0; i < fields_count; i++)
		free(fields[i]);
	free(fields);

	close_files(2, input, output);
}

int main(void)
{
	run_task1();
	run_task2();
	return 0;
}
