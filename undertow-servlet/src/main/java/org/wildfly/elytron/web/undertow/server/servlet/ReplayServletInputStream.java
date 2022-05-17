/*
 * Copyright 2022 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.elytron.web.undertow.server.servlet;

import java.io.IOException;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;

/**
 * <p>Internal class that allows the replay of the InputStream using the
 * direct bytes.</p>
 *
 * @author rmartinc
 */
class ReplayServletInputStream extends ServletInputStream {

    private final byte[] bytes;
    private int idx;
    private ReadListener listener = null;

    public ReplayServletInputStream(byte[] bytes) {
        this.bytes = bytes;
        this.idx = -1;
    }

    @Override
    public boolean isFinished() {
        return idx >= bytes.length - 1;
    }

    @Override
    public boolean isReady() {
        return !isFinished();
    }

    @Override
    public void setReadListener(ReadListener listener) {
        this.listener = listener;
        if (isReady()) {
            try {
                listener.onDataAvailable();
            } catch (IOException e) {
                listener.onError(e);
            }
        } else {
            try {
                listener.onAllDataRead();
            } catch (IOException e) {
                listener.onError(e);
            }
        }
    }

    @Override
    public int read() throws IOException {
        int result = -1;
        if (isReady()) {
            result = bytes[++idx];
            if (isFinished() && listener != null) {
                try {
                    listener.onAllDataRead();
                } catch (IOException e) {
                    listener.onError(e);
                }
            }
        }
        return result;
    }

}
