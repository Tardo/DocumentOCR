/*
 * Copyright 2008-2010 the original author or authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ocr.document.tardo.documentocr.utils;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;


public abstract class DateHelper {

    public static float getAge(final Date birthdate) {
        return getAge(Calendar.getInstance().getTime(), birthdate);
    }

    public static float getAge(final Date current, final Date birthdate) {
        if (birthdate == null) {
            return 0;
        }
        if (current == null) {
            return getAge(birthdate);
        } else {
            final Calendar calend = new GregorianCalendar();
            calend.set(Calendar.HOUR_OF_DAY, 0);
            calend.set(Calendar.MINUTE, 0);
            calend.set(Calendar.SECOND, 0);
            calend.set(Calendar.MILLISECOND, 0);

            calend.setTimeInMillis(current.getTime() - birthdate.getTime());

            float result = 0;
            result = calend.get(Calendar.YEAR) - 1970;
            result += (float) calend.get(Calendar.MONTH) / (float) 12;
            return result;
        }
    }

    public static Date getExpeditionDate(final Date birthday, final Date expiry) {
        Date result = new Date(expiry.getTime());
        final Float age = getAge(birthday);
        final Float diff = getAge(expiry, Calendar.getInstance().getTime());
        if (age < 5) {
            if (diff <= 2) {
                result.setYear(expiry.getYear());
            } else {
                result.setYear(expiry.getYear()-2);
            }
        }
        else if (age >= 5 && age < 30) {
            if (diff <= 5) {
                result.setYear(expiry.getYear()-2);
            } else {
                result.setYear(expiry.getYear()-5);
            }
        }
        else if (age >= 30 && age < 70) {
            if (diff <= 5) {
                result.setYear(expiry.getYear()-5);
            } else {
                result.setYear(expiry.getYear()-10);
            }
        } else {
            return null;
        }
        return result;
    }
}