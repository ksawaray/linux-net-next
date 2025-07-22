/* Rate limiting and statistics for dupnat */
static DEFINE_PER_CPU(unsigned long, dupnat_rate_last);
static DEFINE_PER_CPU(unsigned int, dupnat_rate_tokens);

#define DUPNAT_RATE_LIMIT_BURST 10
#define DUPNAT_RATE_LIMIT_TIMEOUT HZ

static bool nf_dupnat_rate_limit(void)
{
	unsigned long *last = this_cpu_ptr(&dupnat_rate_last);
	unsigned int *tokens = this_cpu_ptr(&dupnat_rate_tokens);
	unsigned long now = jiffies;

	if (time_after(now, *last + DUPNAT_RATE_LIMIT_TIMEOUT)) {
		*tokens = DUPNAT_RATE_LIMIT_BURST;
		*last = now;
	}

	if (*tokens > 0) {
		(*tokens)--;
		return false;
	}

	return true;
}
