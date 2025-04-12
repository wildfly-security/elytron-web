/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2025 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.wildfly.elytron.web.undertow.server;

import static java.lang.Character.isISOControl;
import static java.lang.Character.isSpaceChar;
import static java.lang.Integer.toHexString;
import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * Undertow supports being configured to receive path and query components that have not been fully encoded.
 *
 * In this case they may have been partially encoded so passing through URI to encode again leads to double
 * encoding, this utility class is to encode these by taking a second pass and only encoding the characters
 * that really need it.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UriPartialEncoder {

    enum Component {

        PATH(UriPartialEncoder::pathIsAllowed),
        QUERY(UriPartialEncoder::queryIsAllowed);

        private final CharPredicate predicate;

        Component(CharPredicate predicate) {
            this.predicate = predicate;
        }

        boolean isAllowed(final char candidate) {
            return predicate.test(candidate);
        }

    };


    static String partialEncode(final String value, final Component component) {
        checkNotNullParam("value", value);
        checkNotNullParam("component", component);

        StringBuilder sb = new StringBuilder();
        int length = value.length();
        for (int i = 0; i < length; i++) {
            final char c = value.charAt(i);

            if ((c == '%' && i < length - 2 && testPercentEncoded(value.substring(i, i + 3)))
                || component.isAllowed(c)
                || !percentEncode(c, sb)) {
                // It was (first match wins):
                //  - Part of a correctly percent encoded sequence.
                //  - Allowed by the component.
                //  - Not successfully percent encoded.
                sb.append(c);
            }
        }

        return sb.toString();
    }

    private static boolean percentEncode(final char current, final StringBuilder destination) {
        if (!canEncode(current)) {
            return false;
        }

        destination.append('%');
        // We know it is not bigger than 0xFF
        destination.append(toHexString(current).toUpperCase());

        return true;
    }

    private static boolean canEncode(final char candidate) {
        return candidate <= 0xFF;
    }

    private static boolean isUnreserved(final char candidate) {
        if (  (candidate >= 'A' && candidate <= 'Z')
            || (candidate >= 'a' && candidate <= 'z')
            || (candidate >= '0' && candidate <= '9') ) {

            return true;
        }
        switch (candidate) {
            case '_':
            case '-':
            case '!':
            case '.':
            case '~':
            case '\'':
            case '(':
            case ')':
            case '*':
                return true;
            default:
                return false;
        }
    }

    private static boolean isPunct(final char candidate) {
        switch (candidate) {
            case ',':
            case ';':
            case ':':
            case '$':
            case '&':
            case '+':
            case '=':
                return true;
            default:
                return false;
        }
    }

    private static boolean isReserved(final char candidate) {
        if (isPunct(candidate)) {
            return true;
        }

        switch (candidate) {
            case '?':
            case '/':
            case '[':
            case ']':
            case '@':
                return true;
            default:
                return false;
        }
    }

    private static boolean isOther(final char candidate) {
        return isSpaceChar(candidate) && isISOControl(candidate);
    }

    private static boolean isPathAllowed(final char candidate) {
        return candidate == '/' || candidate == '@';
    }

    private static boolean pathIsAllowed(final char candidate) {
        return ((isUnreserved(candidate) ||
                isPunct(candidate) ||
                isPathAllowed(candidate)) && !isOther(candidate));
    }

    private static boolean queryIsAllowed(final char candidate) {
        return (isUnreserved(candidate) || isReserved(candidate)) && !isOther(candidate);
    }

    private static boolean testPercentEncoded(final String value) {
        if (value.length() == 3) {
            return isHex(value.charAt(1)) && isHex(value.charAt(2));
        }

        // Should not be reachable.
        return false;
    }

    private static boolean isHex(final char value) {
        return (value >= '0' && value <= '9')
                || (value >= 'A' && value <= 'F')
                || (value >= 'a' && value <= 'f');
    }

    interface CharPredicate {
        boolean test(char c);
    }
}
