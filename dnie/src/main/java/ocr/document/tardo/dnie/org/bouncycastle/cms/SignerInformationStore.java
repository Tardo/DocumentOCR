package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignerInformationStore {
    private List all = new ArrayList();
    private Map table = new HashMap();

    public SignerInformationStore(Collection collection) {
        for (SignerInformation signerInformation : collection) {
            SignerId sid = signerInformation.getSID();
            List list = (ArrayList) this.table.get(sid);
            if (list == null) {
                list = new ArrayList(1);
                this.table.put(sid, list);
            }
            list.add(signerInformation);
        }
        this.all = new ArrayList(collection);
    }

    public SignerInformation get(SignerId signerId) {
        Collection signers = getSigners(signerId);
        return signers.size() == 0 ? null : (SignerInformation) signers.iterator().next();
    }

    public Collection getSigners() {
        return new ArrayList(this.all);
    }

    public Collection getSigners(SignerId signerId) {
        if (signerId.getIssuer() == null || signerId.getSubjectKeyIdentifier() == null) {
            ArrayList arrayList = (ArrayList) this.table.get(signerId);
            return arrayList == null ? new ArrayList() : new ArrayList(arrayList);
        } else {
            Collection arrayList2 = new ArrayList();
            Collection signers = getSigners(new SignerId(signerId.getIssuer(), signerId.getSerialNumber()));
            if (signers != null) {
                arrayList2.addAll(signers);
            }
            signers = getSigners(new SignerId(signerId.getSubjectKeyIdentifier()));
            if (signers == null) {
                return arrayList2;
            }
            arrayList2.addAll(signers);
            return arrayList2;
        }
    }

    public int size() {
        return this.all.size();
    }
}
