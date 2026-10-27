import csv


CSV_FIELD_SIZE_LIMIT = 250 * 1024 * 1024
csv.field_size_limit(max(csv.field_size_limit(), CSV_FIELD_SIZE_LIMIT))
