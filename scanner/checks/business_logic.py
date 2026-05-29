from difflib import SequenceMatcher
import concurrent.futures


class BusinessLogicCheck:

    PRICE_PARAMS = [
        "price",
        "amount",
        "total",
        "cost",
        "value",
        "payment"
    ]

    QUANTITY_PARAMS = [
        "quantity",
        "qty",
        "count",
        "stock"
    ]

    ROLE_PARAMS = [
        "role",
        "admin",
        "is_admin",
        "permission",
        "access"
    ]

    COUPON_PARAMS = [
        "coupon",
        "promo",
        "discount",
        "voucher",
        "gift"
    ]

    PRICE_MUTATIONS = [
        "-1",
        "-100",
        "0",
        "0.01",
        "999999"
    ]

    QUANTITY_MUTATIONS = [
        "-1",
        "0",
        "999999",
        "2147483647"
    ]

    ROLE_MUTATIONS = [
        "admin",
        "true",
        "1",
        "superadmin"
    ]

    @classmethod
    def run(cls, http, forms):

        findings = []

        for form in forms:

            if form["method"].upper() != "POST":
                continue

            findings.extend(
                cls._test_price_manipulation(http, form)
            )

            findings.extend(
                cls._test_quantity_manipulation(http, form)
            )

            findings.extend(
                cls._test_role_manipulation(http, form)
            )

            findings.extend(
                cls._test_coupon_abuse(http, form)
            )

            findings.extend(
                cls._test_race_condition(http, form)
            )

        return findings

    @classmethod
    def _baseline_request(cls, http, form):

        data = {}

        for inp in form["inputs"]:
            data[inp["name"]] = inp["value"] or "1"

        try:

            response = http.post(
                form["action"],
                data=data
            )

            return response

        except Exception:
            return None

    @classmethod
    def _test_price_manipulation(cls, http, form):

        findings = []

        baseline = cls._baseline_request(http, form)

        if not baseline:
            return findings

        baseline_text = baseline.text
        baseline_status = baseline.status_code

        for inp in form["inputs"]:

            param = inp["name"].lower()

            if not any(p in param for p in cls.PRICE_PARAMS):
                continue

            for mutation in cls.PRICE_MUTATIONS:

                try:

                    data = {}

                    for field in form["inputs"]:

                        if field["name"] == inp["name"]:
                            data[field["name"]] = mutation
                        else:
                            data[field["name"]] = field["value"] or "1"

                    response = http.post(
                        form["action"],
                        data=data
                    )

                    if not response:
                        continue

                    if cls._is_interesting(
                        baseline_text,
                        response.text,
                        baseline_status,
                        response.status_code
                    ):

                        findings.append({
                            "type": "Business Logic - Price Manipulation",
                            "severity": "CRITICAL",
                            "severity_score": 9,
                            "url": form["action"],
                            "param": inp["name"],
                            "payload": mutation,
                            "evidence": (
                                f"Application accepted suspicious "
                                f"price value: {mutation}"
                            ),
                            "description": (
                                "Application may allow price tampering "
                                "or financial manipulation."
                            ),
                            "recommendation": (
                                "Validate prices strictly on server-side "
                                "and never trust client values."
                            )
                        })

                        print(
                            f"[BUSINESS LOGIC] "
                            f"Price manipulation detected "
                            f"{inp['name']}={mutation}"
                        )

                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _test_quantity_manipulation(cls, http, form):

        findings = []

        baseline = cls._baseline_request(http, form)

        if not baseline:
            return findings

        baseline_text = baseline.text
        baseline_status = baseline.status_code

        for inp in form["inputs"]:

            param = inp["name"].lower()

            if not any(p in param for p in cls.QUANTITY_PARAMS):
                continue

            for mutation in cls.QUANTITY_MUTATIONS:

                try:

                    data = {}

                    for field in form["inputs"]:

                        if field["name"] == inp["name"]:
                            data[field["name"]] = mutation
                        else:
                            data[field["name"]] = field["value"] or "1"

                    response = http.post(
                        form["action"],
                        data=data
                    )

                    if not response:
                        continue

                    if cls._is_interesting(
                        baseline_text,
                        response.text,
                        baseline_status,
                        response.status_code
                    ):

                        findings.append({
                            "type": "Business Logic - Quantity Manipulation",
                            "severity": "HIGH",
                            "severity_score": 8,
                            "url": form["action"],
                            "param": inp["name"],
                            "payload": mutation,
                            "evidence": (
                                f"Application accepted suspicious "
                                f"quantity value: {mutation}"
                            ),
                            "description": (
                                "Application may allow quantity abuse."
                            ),
                            "recommendation": (
                                "Implement quantity validation "
                                "and server-side limits."
                            )
                        })

                        print(
                            f"[BUSINESS LOGIC] "
                            f"Quantity manipulation detected "
                            f"{inp['name']}={mutation}"
                        )

                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _test_role_manipulation(cls, http, form):

        findings = []

        for inp in form["inputs"]:

            param = inp["name"].lower()

            if not any(p in param for p in cls.ROLE_PARAMS):
                continue

            for mutation in cls.ROLE_MUTATIONS:

                try:

                    data = {}

                    for field in form["inputs"]:

                        if field["name"] == inp["name"]:
                            data[field["name"]] = mutation
                        else:
                            data[field["name"]] = field["value"] or "1"

                    response = http.post(
                        form["action"],
                        data=data
                    )

                    if not response:
                        continue

                    if (
                        response.status_code in [200, 201]
                        and (
                            "admin" in response.text.lower()
                            or "dashboard" in response.text.lower()
                        )
                    ):

                        findings.append({
                            "type": "Business Logic - Role Escalation",
                            "severity": "CRITICAL",
                            "severity_score": 10,
                            "url": form["action"],
                            "param": inp["name"],
                            "payload": mutation,
                            "evidence": (
                                f"Role parameter accepted value: "
                                f"{mutation}"
                            ),
                            "description": (
                                "Application may allow privilege escalation."
                            ),
                            "recommendation": (
                                "Enforce authorization checks "
                                "server-side."
                            )
                        })

                        print(
                            f"[BUSINESS LOGIC] "
                            f"Role escalation detected "
                            f"{inp['name']}={mutation}"
                        )

                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _test_coupon_abuse(cls, http, form):

        findings = []

        for inp in form["inputs"]:

            param = inp["name"].lower()

            if not any(p in param for p in cls.COUPON_PARAMS):
                continue

            try:

                data = {}

                for field in form["inputs"]:
                    data[field["name"]] = (
                        field["value"] or "1"
                    )

                data[inp["name"]] = "DISCOUNT100"

                response1 = http.post(
                    form["action"],
                    data=data
                )

                response2 = http.post(
                    form["action"],
                    data=data
                )

                if (
                    response1
                    and response2
                    and response1.status_code == 200
                    and response2.status_code == 200
                ):

                    findings.append({
                        "type": "Business Logic - Coupon Reuse",
                        "severity": "MEDIUM",
                        "severity_score": 6,
                        "url": form["action"],
                        "param": inp["name"],
                        "payload": "DISCOUNT100",
                        "evidence": (
                            "Same coupon request "
                            "accepted multiple times."
                        ),
                        "description": (
                            "Application may allow coupon reuse."
                        ),
                        "recommendation": (
                            "Implement single-use "
                            "coupon validation."
                        )
                    })

                    print(
                        f"[BUSINESS LOGIC] "
                        f"Coupon reuse detected"
                    )

            except Exception:
                continue

        return findings

    @classmethod
    def _test_race_condition(cls, http, form):

        findings = []

        try:

            data = {}

            for field in form["inputs"]:
                data[field["name"]] = (
                    field["value"] or "1"
                )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=5
            ) as executor:

                futures = [
                    executor.submit(
                        http.post,
                        form["action"],
                        data=data
                    )
                    for _ in range(5)
                ]

                responses = [
                    f.result()
                    for f in concurrent.futures.as_completed(futures)
                ]

            success_count = sum(
                1
                for r in responses
                if r and r.status_code in [200, 201]
            )

            if success_count >= 3:

                findings.append({
                    "type": "Business Logic - Race Condition",
                    "severity": "CRITICAL",
                    "severity_score": 10,
                    "url": form["action"],
                    "param": None,
                    "payload": None,
                    "evidence": (
                        f"{success_count} simultaneous "
                        f"requests succeeded."
                    ),
                    "description": (
                        "Application may be vulnerable "
                        "to race conditions."
                    ),
                    "recommendation": (
                        "Implement locking, transactions, "
                        "and idempotency protection."
                    )
                })

                print(
                    f"[BUSINESS LOGIC] "
                    f"Race condition detected"
                )

        except Exception:
            pass

        return findings

    @classmethod
    def _is_interesting(
        cls,
        baseline_text,
        mutated_text,
        baseline_status,
        mutated_status
    ):

        if baseline_status != mutated_status:
            return True

        len_diff = abs(
            len(baseline_text) - len(mutated_text)
        )

        if len_diff > 50:
            return True

        similarity = SequenceMatcher(
            None,
            baseline_text,
            mutated_text
        ).ratio()

        if similarity < 0.85:
            return True

        return False