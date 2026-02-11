
package com.example.crypto.processor;

import com.example.crypto.annotation.CryptoKeyGeneration;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import java.util.*;

@SupportedAnnotationTypes("com.example.crypto.annotation.CryptoKeyGeneration")
@SupportedSourceVersion(SourceVersion.RELEASE_17)
@SupportedOptions({"minAesKeySize","minRsaKeySize","allowedCurves","banPrivateExport"})
public class CryptoKeyGenPolicyProcessor extends AbstractProcessor {
    private int minAes; private int minRsa; private Set<String> curves; private boolean banExport;

    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
        minAes = Integer.parseInt(processingEnv.getOptions().getOrDefault("minAesKeySize","128"));
        minRsa = Integer.parseInt(processingEnv.getOptions().getOrDefault("minRsaKeySize","2048"));
        curves = new HashSet<>(Arrays.asList(processingEnv.getOptions().getOrDefault("allowedCurves","secp256r1,secp384r1,secp521r1").split(",")));
        banExport = Boolean.parseBoolean(processingEnv.getOptions().getOrDefault("banPrivateExport","true"));
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (Element e : roundEnv.getElementsAnnotatedWith(CryptoKeyGeneration.class)) {
            CryptoKeyGeneration ann = e.getAnnotation(CryptoKeyGeneration.class);
            if (ann == null) continue;
            if (ann.algorithm().equalsIgnoreCase("AES") && ann.keySize() < minAes) {
                error(e, "AES keySize %d below compile-time policy min %d", ann.keySize(), minAes);
            }
            if (ann.algorithm().equalsIgnoreCase("RSA") && ann.keySize() < minRsa) {
                error(e, "RSA keySize %d below compile-time policy min %d", ann.keySize(), minRsa);
            }
            if (ann.algorithm().equalsIgnoreCase("EC")) {
                String crv = ann.curve().isBlank()?"secp256r1":ann.curve();
                if (!curves.contains(crv)) {
                    error(e, "EC curve %s not in allowed set %s", crv, curves);
                }
            }
            if (banExport && ann.exportPrivate()) {
                error(e, "exportPrivate=true is banned by compile-time policy");
            }
        }
        return false;
    }

    private void error(Element e, String fmt, Object... args) {
        processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, String.format(fmt, args), e);
    }
}
