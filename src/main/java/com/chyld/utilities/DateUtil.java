package com.chyld.utilities;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class DateUtil {

    public static Date toJavaDate(LocalDate localDate) {
        Instant localDateInstant = Instant.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()));
        return Date.from(localDateInstant);
    }
}
